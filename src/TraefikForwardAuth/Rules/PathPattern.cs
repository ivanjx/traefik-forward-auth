using System;
using System.Collections.Generic;

namespace TraefikForwardAuth.Rules;

/// <summary>
/// Full-string path glob matching. <c>*</c> matches any characters except <c>/</c>;
/// <c>**</c> matches across segments. All other characters are literal. Matching is
/// case-sensitive and uses dynamic programming, so no pattern can backtrack catastrophically.
/// </summary>
public static class PathPattern
{
    public static bool IsMatch(string pattern, string path)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(path);

        var tokens = Tokenize(pattern);
        var previous = new bool[path.Length + 1];
        previous[0] = true;

        foreach (var token in tokens)
        {
            var current = new bool[path.Length + 1];

            switch (token.Kind)
            {
                case PathTokenKind.SingleStar:
                    current[0] = previous[0];

                    for (var i = 1; i <= path.Length; i++)
                    {
                        current[i] = previous[i] || (current[i - 1] && path[i - 1] != '/');
                    }

                    break;

                case PathTokenKind.DoubleStar:
                    current[0] = previous[0];

                    for (var i = 1; i <= path.Length; i++)
                    {
                        current[i] = previous[i] || current[i - 1];
                    }

                    break;

                default:
                    for (var i = 1; i <= path.Length; i++)
                    {
                        current[i] = previous[i - 1] && path[i - 1] == token.Literal;
                    }

                    break;
            }

            previous = current;
        }

        return previous[path.Length];
    }

    private static List<PathToken> Tokenize(string pattern)
    {
        var tokens = new List<PathToken>(pattern.Length);

        for (var i = 0; i < pattern.Length; i++)
        {
            if (pattern[i] != '*')
            {
                tokens.Add(new PathToken(PathTokenKind.Literal, pattern[i]));
                continue;
            }

            var length = 1;

            while (i + length < pattern.Length && pattern[i + length] == '*')
            {
                length++;
            }

            tokens.Add(length >= 2
                ? new PathToken(PathTokenKind.DoubleStar, '\0')
                : new PathToken(PathTokenKind.SingleStar, '\0'));

            i += length - 1;
        }

        return tokens;
    }

    private enum PathTokenKind
    {
        Literal,
        SingleStar,
        DoubleStar
    }

    private readonly record struct PathToken(PathTokenKind Kind, char Literal);
}
