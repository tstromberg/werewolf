/* Keep libc's private regex_t layout on the C side of the ABI. */
#include <regex.h>

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
