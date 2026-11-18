using System.Globalization;
using System.Text;

namespace TraefikForwardAuth.Logging;

public enum TfaLogLevel
{
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5
}

public enum TfaLogFormat
{
    Text,
    Json,
    Pretty
}

/// <summary>
/// Logrus-compatible console logger. Fatal and panic configuration levels both map to Critical.
/// </summary>
public sealed class TfaLogger
{
    private static readonly string[] LevelNames = ["trace", "debug", "info", "warning", "error", "fatal"];
    private readonly Lock _gate = new();
    private readonly TextWriter _output;
    private readonly TimeProvider _timeProvider;
    private readonly TfaLogLevel _minimum;

    public TfaLogger(TfaLogLevel minimum, TfaLogFormat format, TextWriter? output = null, TimeProvider? timeProvider = null)
    {
        _minimum = minimum;
        Format = format;
        _output = output ?? Console.Out;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public TfaLogFormat Format { get; }

    public TfaLogLevel MinimumLevel => _minimum;

    public bool IsEnabled(TfaLogLevel level) => level >= _minimum;

    public void Trace(string message, params (string Key, object? Value)[] fields) => Write(TfaLogLevel.Trace, message, fields);

    public void Debug(string message, params (string Key, object? Value)[] fields) => Write(TfaLogLevel.Debug, message, fields);

    public void Info(string message, params (string Key, object? Value)[] fields) => Write(TfaLogLevel.Info, message, fields);

    public void Warn(string message, params (string Key, object? Value)[] fields) => Write(TfaLogLevel.Warn, message, fields);

    public void Error(string message, params (string Key, object? Value)[] fields) => Write(TfaLogLevel.Error, message, fields);

    public void Critical(string message, params (string Key, object? Value)[] fields) => Write(TfaLogLevel.Critical, message, fields);

    public void Write(TfaLogLevel level, string message, params (string Key, object? Value)[] fields)
    {
        if (!IsEnabled(level))
        {
            return;
        }

        var timestamp = _timeProvider.GetUtcNow();
        var line = Format switch
        {
            TfaLogFormat.Json => FormatJson(level, timestamp, message, fields),
            TfaLogFormat.Pretty => FormatPretty(level, timestamp, message, fields),
            _ => FormatText(level, timestamp, message, fields)
        };

        lock (_gate)
        {
            _output.WriteLine(line);
            _output.Flush();
        }
    }

    private static string FormatText(TfaLogLevel level, DateTimeOffset timestamp, string message, (string Key, object? Value)[] fields)
    {
        var builder = new StringBuilder();
        builder.Append("time=\"").Append(FormatTimestamp(timestamp)).Append('"');
        builder.Append(" level=").Append(LevelNames[(int)level]);
        builder.Append(" msg=").Append(Quote(message));

        foreach (var field in fields.OrderBy(field => field.Key, StringComparer.Ordinal))
        {
            builder.Append(' ').Append(field.Key).Append('=').Append(Quote(FormatValue(field.Value)));
        }

        return builder.ToString();
    }

    private static string FormatJson(TfaLogLevel level, DateTimeOffset timestamp, string message, (string Key, object? Value)[] fields)
    {
        var builder = new StringBuilder();
        builder.Append('{');
        AppendJsonProperty(builder, "level", LevelNames[(int)level]);
        builder.Append(',');
        AppendJsonProperty(builder, "msg", message);
        builder.Append(',');
        AppendJsonProperty(builder, "time", FormatTimestamp(timestamp));

        foreach (var field in fields.OrderBy(field => field.Key, StringComparer.Ordinal))
        {
            builder.Append(',');
            builder.Append('"').Append(JsonEscape(field.Key)).Append("\":");

            switch (field.Value)
            {
                case null:
                    builder.Append("null");
                    break;
                case bool boolean:
                    builder.Append(boolean ? "true" : "false");
                    break;
                case int or long or short or byte or uint or ulong or ushort or sbyte:
                    builder.Append(Convert.ToString(field.Value, CultureInfo.InvariantCulture));
                    break;
                case double or float or decimal:
                    builder.Append(Convert.ToString(field.Value, CultureInfo.InvariantCulture));
                    break;
                default:
                    builder.Append('"').Append(JsonEscape(FormatValue(field.Value))).Append('"');
                    break;
            }
        }

        builder.Append('}');

        return builder.ToString();
    }

    private static string FormatPretty(TfaLogLevel level, DateTimeOffset timestamp, string message, (string Key, object? Value)[] fields)
    {
        var builder = new StringBuilder();
        builder.Append(LevelNames[(int)level].ToUpperInvariant()).Append('[');
        builder.Append(timestamp.ToString("HH:mm:ss", CultureInfo.InvariantCulture)).Append("] ");
        builder.Append(message);

        foreach (var field in fields.OrderBy(field => field.Key, StringComparer.Ordinal))
        {
            builder.Append(' ').Append(field.Key).Append('=').Append(FormatValue(field.Value));
        }

        return builder.ToString();
    }

    private static void AppendJsonProperty(StringBuilder builder, string name, string value)
    {
        builder.Append('"').Append(JsonEscape(name)).Append("\":\"").Append(JsonEscape(value)).Append('"');
    }

    private static string FormatTimestamp(DateTimeOffset timestamp) =>
        timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    private static string FormatValue(object? value) => value switch
    {
        null => "",
        IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture) ?? "",
        _ => value.ToString() ?? ""
    };

    private static string Quote(string value)
    {
        if (value.Length == 0)
        {
            return "\"\"";
        }

        var needsQuoting = false;

        foreach (var character in value)
        {
            if (!(char.IsLetterOrDigit(character) || character is '-' or '.' or '_' or '/' or '@' or '^' or '+'))
            {
                needsQuoting = true;
                break;
            }
        }

        return needsQuoting ? "\"" + JsonEscape(value) + "\"" : value;
    }

    private static string JsonEscape(string value)
    {
        var builder = new StringBuilder(value.Length + 8);

        foreach (var character in value)
        {
            switch (character)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (character < ' ')
                    {
                        builder.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(character);
                    }

                    break;
            }
        }

        return builder.ToString();
    }
}
