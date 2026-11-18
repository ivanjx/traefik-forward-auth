using System;
using System.Collections.Generic;
using System.Text;

namespace TraefikForwardAuth.Rules;

public readonly record struct PathNormalizationResult(bool Success, string Path, string? Error)
{
    public static PathNormalizationResult Ok(string path) => new(true, path, null);

    public static PathNormalizationResult Fail(string error) => new(false, "", error);
}

public static class PathNormalizer
{
    public static PathNormalizationResult Normalize(string? rawPath)
    {
        if (string.IsNullOrEmpty(rawPath))
        {
            return PathNormalizationResult.Ok("/");
        }

        var queryIndex = rawPath.IndexOf('?');
        var path = queryIndex >= 0 ? rawPath[..queryIndex] : rawPath;

        if (path.Length == 0)
        {
            path = "/";
        }

        if (path[0] != '/')
        {
            return PathNormalizationResult.Fail("Path must start with '/'.");
        }

        var validationError = ValidateRawPath(path);

        if (validationError is not null)
        {
            return PathNormalizationResult.Fail(validationError);
        }

        var decoded = PercentDecode(path);

        foreach (var character in decoded)
        {
            if (IsControlCharacter(character))
            {
                return PathNormalizationResult.Fail("Path contains control characters.");
            }
        }

        return PathNormalizationResult.Ok(NormalizeSegments(decoded));
    }

    private static string? ValidateRawPath(string path)
    {
        for (var i = 0; i < path.Length; i++)
        {
            var character = path[i];

            if (character == '%')
            {
                if (i + 2 >= path.Length || !IsHex(path[i + 1]) || !IsHex(path[i + 2]))
                {
                    return "Path contains an invalid percent escape.";
                }

                var high = char.ToUpperInvariant(path[i + 1]);
                var low = char.ToUpperInvariant(path[i + 2]);

                if ((high == '2' && low == 'F') || (high == '5' && low == 'C'))
                {
                    return "Path contains an encoded slash or backslash.";
                }

                i += 2;
                continue;
            }

            if (IsControlCharacter(character))
            {
                return "Path contains control characters.";
            }
        }

        return null;
    }

    private static string PercentDecode(string path)
    {
        var builder = new StringBuilder(path.Length);
        var i = 0;

        while (i < path.Length)
        {
            if (path[i] != '%')
            {
                builder.Append(path[i]);
                i++;
                continue;
            }

            var bytes = new List<byte>();

            while (i < path.Length && path[i] == '%')
            {
                var value = (HexValue(path[i + 1]) << 4) | HexValue(path[i + 2]);
                bytes.Add((byte)value);
                i += 3;
            }

            builder.Append(Encoding.UTF8.GetString(bytes.ToArray()));
        }

        return builder.ToString();
    }

    private static string NormalizeSegments(string path)
    {
        var segments = path.Split('/');
        var stack = new List<string>();

        foreach (var segment in segments)
        {
            if (segment.Length == 0 || segment == ".")
            {
                continue;
            }

            if (segment == "..")
            {
                if (stack.Count > 0)
                {
                    stack.RemoveAt(stack.Count - 1);
                }

                continue;
            }

            stack.Add(segment);
        }

        var last = segments[^1];
        var trailingSlash = path[^1] == '/' || last == "." || last == "..";

        if (stack.Count == 0)
        {
            return "/";
        }

        var joined = string.Join('/', stack);

        return trailingSlash ? "/" + joined + "/" : "/" + joined;
    }

    private static bool IsControlCharacter(char character) => character < (char)0x20 || character == (char)0x7F;

    private static bool IsHex(char character) =>
        character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    private static int HexValue(char character) => character switch
    {
        >= '0' and <= '9' => character - '0',
        >= 'a' and <= 'f' => character - 'a' + 10,
        >= 'A' and <= 'F' => character - 'A' + 10,
        _ => 0
    };
}
