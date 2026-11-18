using Microsoft.AspNetCore.Http;
using RazorSlices;
using TraefikForwardAuth.Auth;
using TraefikForwardAuth.Http;
using TraefikForwardAuth.Policy;
using TraefikForwardAuth.Rules;
using TraefikForwardAuth.Slices;

namespace TraefikForwardAuth.Admin;

/// <summary>
/// Terminal admin pipeline: assets, login endpoints, authentication, antiforgery and routing.
/// Manual dispatch keeps the whole admin surface free of routing metadata and reflection.
/// </summary>
internal sealed class AdminPipeline
{
    private readonly AppRuntime _runtime;

    public AdminPipeline(AppRuntime runtime)
    {
        _runtime = runtime;
    }

    public async Task HandleAsync(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        var path = context.Request.Path.Value ?? "/";
        var method = context.Request.Method;

        try
        {
            if (path.StartsWith("/assets/", StringComparison.Ordinal))
            {
                await ServeAssetAsync(context, path, method);
                return;
            }

            if (HttpMethods.IsGet(method) && path == "/auth/login")
            {
                await _runtime.AdminAuth.HandleLoginAsync(context, cancellationToken);
                return;
            }

            if (HttpMethods.IsGet(method) && path == "/auth/callback")
            {
                await _runtime.AdminAuth.HandleCallbackAsync(context, cancellationToken);
                return;
            }

            var identity = await _runtime.AdminAuth.AuthenticateAsync(context, cancellationToken);

            if (identity is null)
            {
                if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method))
                {
                    var returnUrl = path + context.Request.QueryString;
                    await GoHttpCompat.RedirectAsync(
                        context,
                        "/auth/login?returnUrl=" + Uri.EscapeDataString(returnUrl),
                        StatusCodes.Status307TemporaryRedirect);
                }
                else
                {
                    await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "Unauthorized");
                }

                return;
            }

            if (HttpMethods.IsPost(method) && !await ValidateAntiforgeryAsync(context, identity, cancellationToken))
            {
                return;
            }

            await DispatchAsync(context, identity, path, method, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _runtime.Logger.Error(
                "Admin UI request failed",
                ("method", method),
                ("path", path),
                ("error", exception.Message));

            if (!context.Response.HasStarted)
            {
                await GoHttpCompat.WriteErrorAsync(
                    context,
                    StatusCodes.Status500InternalServerError,
                    "Internal server error");
            }
        }
    }

    private async Task DispatchAsync(
        HttpContext context,
        AdminIdentity identity,
        string path,
        string method,
        CancellationToken cancellationToken)
    {
        if (path == "/")
        {
            if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method))
            {
                await GoHttpCompat.RedirectAsync(context, "/settings");
                return;
            }

            await RenderNotFoundAsync(context, identity);
            return;
        }

        if (path == "/logout")
        {
            if (!HttpMethods.IsGet(method))
            {
                await RenderNotFoundAsync(context, identity);
                return;
            }

            await _runtime.Admin.RevokeSessionAsync(identity.SessionId, identity.Email, cancellationToken);
            _runtime.AdminAuth.SignOut(context);
            await GoHttpCompat.RedirectAsync(context, "/auth/login", StatusCodes.Status303SeeOther);
            return;
        }

        if (path == "/settings")
        {
            if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method))
            {
                await RenderSettingsAsync(context, identity, cancellationToken);
                return;
            }

            if (HttpMethods.IsPost(method))
            {
                await SaveSettingsAsync(context, identity, cancellationToken);
                return;
            }

            await RenderNotFoundAsync(context, identity);
            return;
        }

        if (path == "/settings/rotate-secret" && HttpMethods.IsPost(method))
        {
            await _runtime.Admin.RotateSecretAsync(identity.Email, cancellationToken);
            _runtime.AdminAuth.SignOut(context);
            await GoHttpCompat.RedirectAsync(context, "/auth/login", StatusCodes.Status303SeeOther);
            return;
        }

        if (path == "/providers" && (HttpMethods.IsGet(method) || HttpMethods.IsHead(method)))
        {
            await RenderProvidersAsync(context, identity, cancellationToken);
            return;
        }

        if (path == "/rules" && (HttpMethods.IsGet(method) || HttpMethods.IsHead(method)))
        {
            await RenderRulesAsync(context, identity, cancellationToken);
            return;
        }

        if (path == "/rules/new")
        {
            if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method))
            {
                await RenderNewRuleAsync(context, identity, cancellationToken);
                return;
            }

            if (HttpMethods.IsPost(method))
            {
                await CreateRuleAsync(context, identity, cancellationToken);
                return;
            }

            await RenderNotFoundAsync(context, identity);
            return;
        }

        if (path == "/rules/preview" && HttpMethods.IsPost(method))
        {
            await PreviewRuleAsync(context, cancellationToken);
            return;
        }

        if (path == "/rules/conditions/editor")
        {
            if (!HttpMethods.IsGet(method) && !HttpMethods.IsPost(method))
            {
                await RenderNotFoundAsync(context, identity);
                return;
            }

            await RenderConditionEditorAsync(context, cancellationToken);
            return;
        }

        if (path == "/access")
        {
            if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method))
            {
                await RenderAccessAsync(context, identity, null, cancellationToken);
                return;
            }

            if (HttpMethods.IsPost(method))
            {
                await AddAccessAsync(context, identity, cancellationToken);
                return;
            }

            await RenderNotFoundAsync(context, identity);
            return;
        }

        if (path == "/sessions" && (HttpMethods.IsGet(method) || HttpMethods.IsHead(method)))
        {
            await RenderSessionsAsync(context, identity, admin: false, cancellationToken);
            return;
        }

        if (path == "/admin-sessions" && (HttpMethods.IsGet(method) || HttpMethods.IsHead(method)))
        {
            await RenderSessionsAsync(context, identity, admin: true, cancellationToken);
            return;
        }

        if (path == "/audit" && (HttpMethods.IsGet(method) || HttpMethods.IsHead(method)))
        {
            await RenderAuditAsync(context, identity, cancellationToken);
            return;
        }

        if (path == "/simulate" && HttpMethods.IsPost(method))
        {
            await SimulateAsync(context, cancellationToken);
            return;
        }

        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length == 2)
        {
            switch (segments[0])
            {
                case "providers":
                    if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method))
                    {
                        await RenderProviderAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    if (HttpMethods.IsPost(method))
                    {
                        await SaveProviderAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    break;

                case "rules":
                    if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method))
                    {
                        await RenderRuleAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    if (HttpMethods.IsPost(method))
                    {
                        await UpdateRuleAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    break;

                case "sessions":
                    if (segments[1] == "revoke-email" && HttpMethods.IsPost(method))
                    {
                        await RevokeSessionsForEmailAsync(context, identity, admin: false, cancellationToken);
                        return;
                    }

                    break;

                case "admin-sessions":
                    if (segments[1] == "revoke-email" && HttpMethods.IsPost(method))
                    {
                        await RevokeSessionsForEmailAsync(context, identity, admin: true, cancellationToken);
                        return;
                    }

                    break;
            }
        }

        if (segments.Length == 3)
        {
            switch (segments[0])
            {
                case "providers":
                    if (segments[2] == "delete" && HttpMethods.IsPost(method))
                    {
                        await DeleteProviderAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    if (segments[2] == "test" && HttpMethods.IsPost(method))
                    {
                        await TestProviderAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    break;

                case "rules":
                    if (segments[2] == "toggle" && HttpMethods.IsPost(method))
                    {
                        await ToggleRuleAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    if (segments[2] == "move" && HttpMethods.IsPost(method))
                    {
                        await MoveRuleAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    if (segments[2] == "delete" && HttpMethods.IsPost(method))
                    {
                        await DeleteRuleAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    break;

                case "sessions":
                    if (segments[2] == "revoke" && HttpMethods.IsPost(method))
                    {
                        await RevokeSessionAsync(context, identity, segments[1], admin: false, cancellationToken);
                        return;
                    }

                    break;

                case "admin-sessions":
                    if (segments[2] == "revoke" && HttpMethods.IsPost(method))
                    {
                        await RevokeSessionAsync(context, identity, segments[1], admin: true, cancellationToken);
                        return;
                    }

                    break;

                case "access":
                    if (segments[2] == "delete" && HttpMethods.IsPost(method))
                    {
                        await DeleteAccessAsync(context, identity, segments[1], cancellationToken);
                        return;
                    }

                    break;
            }
        }

        await RenderNotFoundAsync(context, identity);
    }

    private static async Task ServeAssetAsync(HttpContext context, string path, string method)
    {
        if (!HttpMethods.IsGet(method) && !HttpMethods.IsHead(method))
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status404NotFound, "Not found");
            return;
        }

        var bytes = AdminAssets.Read(path);

        if (bytes is null)
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status404NotFound, "Not found");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = AdminAssets.ContentType(path);
        context.Response.ContentLength = bytes.Length;
        context.Response.Headers.CacheControl = "public, max-age=3600";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";

        if (HttpMethods.IsGet(method))
        {
            await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
        }
    }

    private async Task<bool> ValidateAntiforgeryAsync(
        HttpContext context,
        AdminIdentity identity,
        CancellationToken cancellationToken)
    {
        var headerToken = context.Request.Headers["X-CSRF-Token"].FirstOrDefault();
        string? formToken = null;

        if (context.Request.HasFormContentType)
        {
            var form = await ReadFormAsync(context, cancellationToken);

            if (form is null)
            {
                await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid antiforgery token");
                return false;
            }

            formToken = form[AdminForms.TokenField];
        }

        if (_runtime.AdminAuth.ValidateAntiforgeryToken(identity.SessionId, headerToken) ||
            _runtime.AdminAuth.ValidateAntiforgeryToken(identity.SessionId, formToken))
        {
            return true;
        }

        await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid antiforgery token");
        return false;
    }

    private static async Task<IFormCollection?> ReadFormAsync(HttpContext context, CancellationToken cancellationToken)
    {
        if (!context.Request.HasFormContentType)
        {
            return null;
        }

        try
        {
            return await context.Request.ReadFormAsync(cancellationToken);
        }
        catch (InvalidDataException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private async Task RenderSettingsAsync(
        HttpContext context,
        AdminIdentity identity,
        CancellationToken cancellationToken,
        PolicySettings? settings = null,
        string? error = null)
    {
        if (settings is null)
        {
            var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
            settings = configuration.Settings;
        }

        var (flash, isError) = ReadFlash(context);
        var model = new SettingsPageModel
        {
            Layout = Layout(identity, "Settings", "settings", error ?? flash, error is not null || isError),
            Settings = settings
        };

        await RenderAsync(context, Settings.Create(model));
    }

    private async Task SaveSettingsAsync(
        HttpContext context,
        AdminIdentity identity,
        CancellationToken cancellationToken)
    {
        var form = await ReadFormAsync(context, cancellationToken);

        if (form is null)
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid form submission");
            return;
        }

        var current = _runtime.Admin.Snapshot.Settings;
        var parsed = AdminForms.ParseSettings(form, current);

        if (parsed.Errors.Count > 0)
        {
            await RenderSettingsAsync(context, identity, cancellationToken, parsed.Settings, string.Join(" ", parsed.Errors));
            return;
        }

        try
        {
            await _runtime.Admin.UpdateSettingsAsync(parsed.Settings, identity.Email, cancellationToken);
        }
        catch (ArgumentException exception)
        {
            await RenderSettingsAsync(context, identity, cancellationToken, parsed.Settings, exception.Message);
            return;
        }

        await GoHttpCompat.RedirectAsync(context, "/settings?saved=1", StatusCodes.Status303SeeOther);
    }

    private async Task RenderProvidersAsync(
        HttpContext context,
        AdminIdentity identity,
        CancellationToken cancellationToken,
        string? error = null)
    {
        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var rows = configuration.Providers
            .Select(provider => new ProviderRow(provider.Name, AdminUi.Label(provider), provider.HasSecret, provider.ClientId))
            .ToArray();

        var (flash, isError) = ReadFlash(context);
        var model = new ProvidersPageModel
        {
            Layout = Layout(identity, "Providers", "providers", error ?? flash, error is not null || isError),
            Providers = rows
        };

        await RenderAsync(context, TraefikForwardAuth.Slices.Providers.Create(model));
    }

    private async Task RenderProviderAsync(
        HttpContext context,
        AdminIdentity identity,
        string name,
        CancellationToken cancellationToken,
        ProviderDefinition? submitted = null,
        string? error = null)
    {
        if (!IsProviderName(name))
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var existing = configuration.Providers.FirstOrDefault(provider => provider.Name == name);

        if (submitted is null)
        {
            submitted = existing ?? new ProviderDefinition
            {
                Name = name,
                ClientId = "",
                ClientSecret = "",
                TokenStyle = "header"
            };
        }

        var (flash, isError) = ReadFlash(context);
        var model = new ProviderEditPageModel
        {
            Layout = Layout(identity, "Provider " + name, "providers", error ?? flash, error is not null || isError),
            Provider = submitted,
            Exists = existing is not null
        };

        await RenderAsync(context, ProviderEdit.Create(model));
    }

    private async Task SaveProviderAsync(
        HttpContext context,
        AdminIdentity identity,
        string name,
        CancellationToken cancellationToken)
    {
        if (!IsProviderName(name))
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        var form = await ReadFormAsync(context, cancellationToken);

        if (form is null)
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid form submission");
            return;
        }

        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var existing = configuration.Providers.FirstOrDefault(provider => provider.Name == name);
        var provider = AdminForms.ParseProvider(name, form, existing);

        try
        {
            await _runtime.Admin.SaveProviderAsync(provider, identity.Email, cancellationToken);
        }
        catch (ArgumentException exception)
        {
            await RenderProviderAsync(context, identity, name, cancellationToken, provider, exception.Message);
            return;
        }

        await GoHttpCompat.RedirectAsync(
            context,
            "/providers/" + Uri.EscapeDataString(name) + "?saved=1",
            StatusCodes.Status303SeeOther);
    }

    private async Task DeleteProviderAsync(
        HttpContext context,
        AdminIdentity identity,
        string name,
        CancellationToken cancellationToken)
    {
        if (!IsProviderName(name))
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        try
        {
            await _runtime.Admin.DeleteProviderAsync(name, identity.Email, cancellationToken);
        }
        catch (KeyNotFoundException)
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        await GoHttpCompat.RedirectAsync(context, "/providers?saved=1", StatusCodes.Status303SeeOther);
    }

    private async Task TestProviderAsync(
        HttpContext context,
        AdminIdentity identity,
        string name,
        CancellationToken cancellationToken)
    {
        if (!IsProviderName(name))
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        var form = await ReadFormAsync(context, cancellationToken);
        var message = "";

        if (form is null)
        {
            message = "The provider form could not be read.";
        }

        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var existing = configuration.Providers.FirstOrDefault(provider => provider.Name == name);
        var provider = form is null
            ? existing ?? new ProviderDefinition { Name = name }
            : AdminForms.ParseProvider(name, form, existing);

        var errors = provider.ValidationErrors();

        if (errors.Count > 0)
        {
            await RenderPartialAsync(
                context,
                ProviderTest.Create(new ProviderTestModel(name, false, string.Join(" ", errors))));
            return;
        }

        var result = await _runtime.Admin.TestProviderAsync(provider, cancellationToken);
        var text = string.IsNullOrWhiteSpace(result.Message)
            ? (result.Success ? "Connected." : "Connection failed.")
            : result.Message;

        await RenderPartialAsync(context, ProviderTest.Create(new ProviderTestModel(name, result.Success, text + message)));
    }

    private async Task RenderRulesAsync(
        HttpContext context,
        AdminIdentity identity,
        CancellationToken cancellationToken,
        string? error = null)
    {
        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var summaries = _runtime.Admin.Snapshot.Rules.ToDictionary(
            rule => rule.Definition.Id,
            rule => rule.Summary,
            StringComparer.Ordinal);

        var rows = new List<RuleRow>(configuration.Rules.Count);

        for (var i = 0; i < configuration.Rules.Count; i++)
        {
            var rule = configuration.Rules[i];
            var summary = summaries.TryGetValue(rule.Id, out var compiled)
                ? compiled
                : RuleDescriber.Describe(rule);

            rows.Add(new RuleRow(
                rule.Id,
                rule.Name,
                rule.Action == RuleAction.Allow ? "Allow without login" : "Require login",
                rule.Provider ?? "default",
                rule.Enabled,
                summary,
                i == 0,
                i == configuration.Rules.Count - 1));
        }

        var (flash, isError) = ReadFlash(context);
        var model = new RulesPageModel
        {
            Layout = Layout(identity, "Rules", "rules", error ?? flash, error is not null || isError),
            Rules = rows
        };

        await RenderAsync(context, TraefikForwardAuth.Slices.Rules.Create(model));
    }

    private async Task RenderNewRuleAsync(
        HttpContext context,
        AdminIdentity identity,
        CancellationToken cancellationToken,
        RuleDefinition? rule = null,
        IReadOnlyList<string>? errors = null)
    {
        rule ??= new RuleDefinition
        {
            Id = "",
            Name = "",
            Enabled = true,
            Action = RuleAction.Auth,
            Provider = null,
            Position = 0,
            Conditions =
            [
                new ConditionDefinition
                {
                    Field = ConditionField.Host,
                    Operator = ConditionOperator.Is
                }
            ]
        };

        await RenderRuleEditorAsync(context, identity, rule, isNew: true, errors ?? [], cancellationToken);
    }

    private async Task RenderRuleAsync(
        HttpContext context,
        AdminIdentity identity,
        string id,
        CancellationToken cancellationToken,
        RuleDefinition? submitted = null,
        IReadOnlyList<string>? errors = null)
    {
        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var existing = configuration.Rules.FirstOrDefault(rule => rule.Id == id);

        if (existing is null)
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        await RenderRuleEditorAsync(
            context,
            identity,
            submitted ?? existing,
            isNew: false,
            errors ?? [],
            cancellationToken);
    }

    private async Task RenderRuleEditorAsync(
        HttpContext context,
        AdminIdentity identity,
        RuleDefinition rule,
        bool isNew,
        IReadOnlyList<string> errors,
        CancellationToken cancellationToken)
    {
        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var conditions = new List<ConditionRowModel>(rule.Conditions.Count);

        for (var i = 0; i < rule.Conditions.Count; i++)
        {
            var condition = rule.Conditions[i];
            conditions.Add(AdminUi.ConditionRow(
                i,
                condition.Field,
                condition.Operator,
                condition.Name,
                condition.Values,
                condition.Negated));
        }

        var accessEntries = isNew
            ? []
            : configuration.AccessEntries.Where(entry => entry.RuleId == rule.Id).ToArray();

        var (flash, isError) = ReadFlash(context);
        var model = new RuleEditPageModel
        {
            Layout = Layout(
                identity,
                isNew ? "New rule" : "Edit rule",
                "rules",
                errors.Count > 0 ? null : flash,
                !isError && errors.Count == 0 ? false : isError),
            Rule = rule,
            IsNew = isNew,
            ProviderNames = configuration.Providers.Select(provider => provider.Name).ToArray(),
            Errors = errors,
            Summary = RuleDescriber.Describe(rule),
            Conditions = conditions,
            NextConditionIndex = conditions.Count == 0 ? 0 : conditions.Max(condition => condition.Index) + 1,
            AccessEntries = accessEntries
        };

        await RenderAsync(context, RuleEdit.Create(model));
    }

    private async Task CreateRuleAsync(
        HttpContext context,
        AdminIdentity identity,
        CancellationToken cancellationToken)
    {
        var form = await ReadFormAsync(context, cancellationToken);

        if (form is null)
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid form submission");
            return;
        }

        var parsedConditions = AdminForms.ParseConditions(form);
        var parsed = AdminForms.ParseRule(
            form,
            Guid.NewGuid().ToString("N"),
            0,
            parsedConditions.Conditions,
            parsedConditions.Errors);

        if (parsed.Errors.Count > 0)
        {
            await RenderNewRuleAsync(context, identity, cancellationToken, parsed.Rule, parsed.Errors);
            return;
        }

        try
        {
            await _runtime.Admin.CreateRuleAsync(parsed.Rule, identity.Email, cancellationToken);
        }
        catch (ArgumentException exception)
        {
            await RenderNewRuleAsync(context, identity, cancellationToken, parsed.Rule, [exception.Message]);
            return;
        }

        await GoHttpCompat.RedirectAsync(context, "/rules?saved=1", StatusCodes.Status303SeeOther);
    }

    private async Task UpdateRuleAsync(
        HttpContext context,
        AdminIdentity identity,
        string id,
        CancellationToken cancellationToken)
    {
        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var existing = configuration.Rules.FirstOrDefault(rule => rule.Id == id);

        if (existing is null)
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        var form = await ReadFormAsync(context, cancellationToken);

        if (form is null)
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid form submission");
            return;
        }

        var parsedConditions = AdminForms.ParseConditions(form);
        var parsed = AdminForms.ParseRule(
            form,
            id,
            existing.Position,
            parsedConditions.Conditions,
            parsedConditions.Errors);

        if (parsed.Errors.Count > 0)
        {
            await RenderRuleAsync(context, identity, id, cancellationToken, parsed.Rule, parsed.Errors);
            return;
        }

        try
        {
            await _runtime.Admin.UpdateRuleAsync(parsed.Rule, identity.Email, cancellationToken);
        }
        catch (ArgumentException exception)
        {
            await RenderRuleAsync(context, identity, id, cancellationToken, parsed.Rule, [exception.Message]);
            return;
        }

        await GoHttpCompat.RedirectAsync(context, "/rules?saved=1", StatusCodes.Status303SeeOther);
    }

    private async Task PreviewRuleAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var form = await ReadFormAsync(context, cancellationToken);

        if (form is null)
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid form submission");
            return;
        }

        var parsedConditions = AdminForms.ParseConditions(form);
        var parsed = AdminForms.ParseRule(
            form,
            "",
            0,
            parsedConditions.Conditions,
            parsedConditions.Errors);

        var model = new RulePreviewModel
        {
            Summary = RuleDescriber.Describe(parsed.Rule),
            Errors = parsed.Errors
        };

        await RenderPartialAsync(context, RulePreview.Create(model));
    }

    private async Task RenderConditionEditorAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var indexText = context.Request.Query["index"].FirstOrDefault();

        if (string.IsNullOrEmpty(indexText) && context.Request.HasFormContentType)
        {
            var form = await ReadFormAsync(context, cancellationToken);
            indexText = form?["index"];
        }

        if (!int.TryParse(indexText, out var index) || index < 0)
        {
            index = 0;
        }

        ConditionRowModel row;

        if (context.Request.HasFormContentType)
        {
            var form = await ReadFormAsync(context, cancellationToken);
            row = form is null
                ? AdminUi.ConditionRow(index, ConditionField.Host, ConditionOperator.Is, "", [], false)
                : AdminForms.ConditionRowFromForm(form, index);
        }
        else
        {
            row = ConditionRowFromQuery(context.Request.Query, index);
        }

        await RenderPartialAsync(context, ConditionRow.Create(row));
    }

    private static ConditionRowModel ConditionRowFromQuery(IQueryCollection query, int index)
    {
        var fieldText = query[$"Conditions[{index}].Field"].ToString();
        var operatorText = query[$"Conditions[{index}].Operator"].ToString();

        if (!Enum.TryParse<ConditionField>(fieldText, ignoreCase: true, out var field) || !Enum.IsDefined(field))
        {
            field = ConditionField.Host;
        }

        if (!Enum.TryParse<ConditionOperator>(operatorText, ignoreCase: true, out var @operator) ||
            !Enum.IsDefined(@operator))
        {
            @operator = AdminUi.DefaultOperator(field);
        }

        var values = new List<string>();

        foreach (var item in query[$"Conditions[{index}].Values"])
        {
            if (item is null)
            {
                continue;
            }

            foreach (var part in item.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (part.Length > 0)
                {
                    values.Add(part);
                }
            }
        }

        var name = query[$"Conditions[{index}].Name"].ToString();
        var negatedText = query[$"Conditions[{index}].Negated"].ToString();
        var negated = negatedText is "on" or "true" or "1";

        return AdminUi.ConditionRow(index, field, @operator, name, values, negated);
    }

    private async Task ToggleRuleAsync(
        HttpContext context,
        AdminIdentity identity,
        string id,
        CancellationToken cancellationToken)
    {
        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var rule = configuration.Rules.FirstOrDefault(candidate => candidate.Id == id);

        if (rule is null)
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        await _runtime.Admin.SetRuleEnabledAsync(id, !rule.Enabled, identity.Email, cancellationToken);
        await GoHttpCompat.RedirectAsync(context, "/rules?saved=1", StatusCodes.Status303SeeOther);
    }

    private async Task MoveRuleAsync(
        HttpContext context,
        AdminIdentity identity,
        string id,
        CancellationToken cancellationToken)
    {
        var form = await ReadFormAsync(context, cancellationToken);
        var direction = form is null ? "" : AdminForms.Text(form, "direction");

        var delta = direction switch
        {
            "up" => -1,
            "down" => 1,
            _ => 0
        };

        if (delta == 0)
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid direction");
            return;
        }

        try
        {
            await _runtime.Admin.MoveRuleAsync(id, delta, identity.Email, cancellationToken);
        }
        catch (KeyNotFoundException)
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        await GoHttpCompat.RedirectAsync(context, "/rules?saved=1", StatusCodes.Status303SeeOther);
    }

    private async Task DeleteRuleAsync(
        HttpContext context,
        AdminIdentity identity,
        string id,
        CancellationToken cancellationToken)
    {
        try
        {
            await _runtime.Admin.DeleteRuleAsync(id, identity.Email, cancellationToken);
        }
        catch (KeyNotFoundException)
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        await GoHttpCompat.RedirectAsync(context, "/rules?saved=1", StatusCodes.Status303SeeOther);
    }

    private async Task RenderAccessAsync(
        HttpContext context,
        AdminIdentity identity,
        string? error,
        CancellationToken cancellationToken)
    {
        var configuration = await _runtime.Admin.GetConfigurationAsync(cancellationToken);
        var selected = context.Request.Query["rule"].FirstOrDefault();

        if (!string.IsNullOrEmpty(selected) && configuration.Rules.All(rule => rule.Id != selected))
        {
            selected = null;
        }

        var global = configuration.AccessEntries.Where(entry => entry.RuleId is null).ToArray();
        var groups = new List<AccessGroup>();

        foreach (var rule in configuration.Rules)
        {
            if (selected is not null && rule.Id != selected)
            {
                continue;
            }

            var entries = configuration.AccessEntries.Where(entry => entry.RuleId == rule.Id).ToArray();

            if (entries.Length > 0)
            {
                groups.Add(new AccessGroup(rule.Id, rule.Name, entries));
            }
        }

        var (flash, isError) = ReadFlash(context);
        var model = new AccessPageModel
        {
            Layout = Layout(identity, "Users & access", "access", error ?? flash, error is not null || isError),
            GlobalEntries = global,
            RuleGroups = groups,
            Rules = configuration.Rules,
            SelectedRuleId = selected
        };

        await RenderAsync(context, Access.Create(model));
    }

    private async Task AddAccessAsync(
        HttpContext context,
        AdminIdentity identity,
        CancellationToken cancellationToken)
    {
        var form = await ReadFormAsync(context, cancellationToken);

        if (form is null)
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid form submission");
            return;
        }

        var scope = AdminForms.Text(form, "scope");
        var kindText = AdminForms.Text(form, "kind");
        var value = AdminForms.Text(form, "value");
        var role = AdminForms.OptionalText(form, "role");

        if (value.Length == 0)
        {
            await RenderAccessAsync(context, identity, "Value is required.", cancellationToken);
            return;
        }

        AccessKind kind;

        if (kindText == "domain")
        {
            kind = AccessKind.Domain;
        }
        else if (kindText == "email")
        {
            kind = AccessKind.Email;
        }
        else
        {
            await RenderAccessAsync(context, identity, "Kind must be email or domain.", cancellationToken);
            return;
        }

        var entry = new AccessEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            RuleId = scope is "" or "global" ? null : scope,
            Kind = kind,
            Value = value,
            Role = role
        };

        try
        {
            await _runtime.Admin.AddAccessEntryAsync(entry, identity.Email, cancellationToken);
        }
        catch (ArgumentException exception)
        {
            await RenderAccessAsync(context, identity, exception.Message, cancellationToken);
            return;
        }

        await GoHttpCompat.RedirectAsync(context, "/access?saved=1", StatusCodes.Status303SeeOther);
    }

    private async Task DeleteAccessAsync(
        HttpContext context,
        AdminIdentity identity,
        string id,
        CancellationToken cancellationToken)
    {
        try
        {
            await _runtime.Admin.DeleteAccessEntryAsync(id, identity.Email, cancellationToken);
        }
        catch (KeyNotFoundException)
        {
            await RenderNotFoundAsync(context, identity);
            return;
        }

        await GoHttpCompat.RedirectAsync(context, "/access?saved=1", StatusCodes.Status303SeeOther);
    }

    private async Task RenderSessionsAsync(
        HttpContext context,
        AdminIdentity identity,
        bool admin,
        CancellationToken cancellationToken,
        string? error = null)
    {
        var email = context.Request.Query["email"].FirstOrDefault();
        var kind = admin ? SessionKind.Admin : SessionKind.ForwardAuth;
        var sessions = await _runtime.Admin.ListSessionsAsync(
            kind,
            string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
            cancellationToken);

        var (flash, isError) = ReadFlash(context);
        var model = new SessionsPageModel
        {
            Layout = Layout(
                identity,
                admin ? "Admin sessions" : "Sessions",
                admin ? "admin-sessions" : "sessions",
                error ?? flash,
                error is not null || isError),
            Sessions = sessions,
            EmailFilter = email,
            CurrentSessionId = identity.SessionId,
            AdminSessions = admin
        };

        await RenderAsync(context, Sessions.Create(model));
    }

    private async Task RevokeSessionsForEmailAsync(
        HttpContext context,
        AdminIdentity identity,
        bool admin,
        CancellationToken cancellationToken)
    {
        var form = await ReadFormAsync(context, cancellationToken);

        if (form is null)
        {
            await GoHttpCompat.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid form submission");
            return;
        }

        var email = AdminForms.Text(form, "email");

        if (email.Length == 0)
        {
            await RenderSessionsAsync(context, identity, admin, cancellationToken, "Email is required.");
            return;
        }

        var kind = admin ? SessionKind.Admin : SessionKind.ForwardAuth;
        await _runtime.Admin.RevokeSessionsForEmailAsync(email, kind, identity.Email, cancellationToken);

        await GoHttpCompat.RedirectAsync(
            context,
            (admin ? "/admin-sessions" : "/sessions") + "?saved=1",
            StatusCodes.Status303SeeOther);
    }

    private async Task RevokeSessionAsync(
        HttpContext context,
        AdminIdentity identity,
        string id,
        bool admin,
        CancellationToken cancellationToken)
    {
        await _runtime.Admin.RevokeSessionAsync(id, identity.Email, cancellationToken);

        if (admin && id == identity.SessionId)
        {
            _runtime.AdminAuth.SignOut(context);
            await GoHttpCompat.RedirectAsync(context, "/auth/login", StatusCodes.Status303SeeOther);
            return;
        }

        await GoHttpCompat.RedirectAsync(
            context,
            (admin ? "/admin-sessions" : "/sessions") + "?saved=1",
            StatusCodes.Status303SeeOther);
    }

    private async Task RenderAuditAsync(
        HttpContext context,
        AdminIdentity identity,
        CancellationToken cancellationToken)
    {
        var entries = await _runtime.Admin.ListAuditAsync(500, cancellationToken);
        var model = new AuditPageModel
        {
            Layout = Layout(identity, "Audit", "audit"),
            Entries = entries
        };

        await RenderAsync(context, Audit.Create(model));
    }

    private async Task SimulateAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var form = await ReadFormAsync(context, cancellationToken);
        SimulateResultModel model;

        if (form is null)
        {
            model = new SimulateResultModel { Error = "The simulation form could not be read." };
        }
        else
        {
            var (request, error) = AdminForms.ParseSimulation(form);

            model = error is not null || request is null
                ? new SimulateResultModel { Error = error ?? "The request could not be parsed." }
                : new SimulateResultModel { Request = request, Result = _runtime.Admin.Simulate(request) };
        }

        await RenderPartialAsync(context, SimulateResult.Create(model));
    }

    private static (string? Flash, bool IsError) ReadFlash(HttpContext context)
    {
        var error = context.Request.Query["error"].ToString();

        if (!string.IsNullOrEmpty(error))
        {
            return (error, true);
        }

        var saved = context.Request.Query["saved"].ToString();

        if (saved == "1")
        {
            return ("Saved.", false);
        }

        return (null, false);
    }

    private LayoutModel Layout(
        AdminIdentity identity,
        string title,
        string active,
        string? flash = null,
        bool flashIsError = false) =>
        new()
        {
            Title = title,
            Active = active,
            AdminEmail = identity.Email,
            AntiforgeryToken = _runtime.AdminAuth.GetAntiforgeryToken(identity.SessionId),
            Flash = flash,
            FlashIsError = flashIsError
        };

    private async Task RenderNotFoundAsync(HttpContext context, AdminIdentity identity)
    {
        var model = new NotFoundPageModel
        {
            Layout = Layout(identity, "Not found", "")
        };

        await RenderAsync(context, NotFound.Create(model), StatusCodes.Status404NotFound);
    }

    private static Task RenderAsync(HttpContext context, RazorSlice slice, int status = StatusCodes.Status200OK)
    {
        slice.StatusCode = status;
        context.Response.ContentType = "text/html; charset=utf-8";

        return ((IResult)slice).ExecuteAsync(context);
    }

    private static Task RenderPartialAsync(HttpContext context, RazorSlice slice) => RenderAsync(context, slice);

    private static bool IsProviderName(string name) =>
        name is ProviderDefinition.Google or ProviderDefinition.Oidc or ProviderDefinition.GenericOAuth;
}
