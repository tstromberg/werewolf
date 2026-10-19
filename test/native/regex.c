/* Keep libc's private regex_t layout on the C side of the ABI. */
#include <regex.h>
#include <stddef.h>

int werewolf_regex_match(const char *pattern, const char *text) {
    regex_t expression;
    if (regcomp(&expression, pattern, REG_EXTENDED | REG_NOSUB) != 0)
        return -1;
    int result = regexec(&expression, text, 0, 0, 0);
    regfree(&expression);
    if (result == 0)
        return 1;
    return result == REG_NOMATCH ? 0 : -1;
}

/* One nonempty group in one match. Repeated matches are ambiguous. */
int werewolf_regex_capture(const char *pattern, const char *text,
                           size_t *start, size_t *end) {
    regex_t expression;
    regmatch_t match[2], other;
    if (regcomp(&expression, pattern, REG_EXTENDED) != 0)
        return -1;
    int result = -1;
    if (expression.re_nsub != 1)
        goto done;
    int found = regexec(&expression, text, 2, match, 0);
    if (found == REG_NOMATCH) {
        result = 0;
        goto done;
    }
    if (found != 0 || match[1].rm_so < 0 || match[1].rm_eo <= match[1].rm_so)
        goto done;
    /* Advance one byte from the match's start to catch overlapping matches. */
    found = regexec(&expression, text + match[0].rm_so + 1, 1, &other, REG_NOTBOL);
    if (found == 0) {
        result = 2;
        goto done;
    }
    if (found != REG_NOMATCH)
        goto done;
    *start = (size_t)match[1].rm_so;
    *end = (size_t)match[1].rm_eo;
    result = 1;
done:
    regfree(&expression);
    return result;
}
