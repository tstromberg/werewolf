# Command manuals

Guest commands have a Markdown manual beside their source: `NAME.1.md` for user
commands, `NAME.8.md` for administration and boot helpers. The build compiles these
to BSD mdoc and installs them under `/usr/share/man` in the command's overlay and
APK. Playground includes `man`. Host-only programs keep their READMEs.

The compiler is [tools/mdoc.zig](../tools/mdoc.zig), a build-host program using only
Zig's standard library. It accepts the small Markdown dialect below. Its output
uses semantic mdoc macros, so mandoc supplies the typography, spacing, synopsis
layout and cross references familiar to a NetBSD reader.

## Write a page

Start with a title, explicit revision date and operating system, then NAME,
SYNOPSIS and DESCRIPTION, in that order:

```markdown
# sample(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

sample — describe the command in a few words

## SYNOPSIS

**sample** [**-v**] [**-o** *file*] *operand*

## DESCRIPTION

The **sample** utility does one job.

- **-v**

  Write progress to standard error.

- **-o** *file*

  Write output to *file*.
```

Use conventional sections as needed: ENVIRONMENT, FILES, EXIT STATUS, EXAMPLES,
SEE ALSO, HISTORY, AUTHORS, CAVEATS and BUGS. Section headings use uppercase words.
Use `### Heading` for a subsection. Keep the prose direct; explain invocation,
defaults, restrictions and failure behavior. Wrap source lines at 88 columns,
preferably breaking between sentences. Blank lines separate paragraphs and
alternative invocations in SYNOPSIS.

## Inline text

| Markdown | Meaning | mdoc |
| --- | --- | --- |
| `**sample**` | This command, or the first word of a synopsis | Nm |
| `**-v**`, `**--verbose**` | An option | Fl |
| `**status**` | Another bold keyword | Cm |
| `*file*` | An argument | Ar |
| Code span starting with `/` or `~/` | A pathname | Pa |
| Code span such as `PATH` in ENVIRONMENT | An environment variable | Ev |
| Any other code span | Literal text | Li |
| `other(8)` | A manual reference | Xr |
| `[**-o** *file*]` in a synopsis or list term | An optional group | Oo, Oc |

Optional groups may nest. Every synopsis starts with a bold command. Put spaces
between inline spans in prose; put punctuation outside the span. Escape literal
Markdown punctuation with a backslash, or enclose it in a code span. Underscores
are ordinary characters. Literal brackets outside synopses and list terms need
escaping or a code span.

## Lists and examples

Use a Markdown list item for a term, a blank line, then its description indented
by two spaces. Additional indented paragraphs belong to the same description.
The compiler produces a tagged list; FILES uses the customary narrow indentation,
while other lists align short terms and let long ones wrap. Do not nest lists.

Fence examples with three backticks, optionally followed by `sh` or `text`.
Their contents are literal and indented in the manual. Links, HTML, tables,
numbered lists, images and raw roff are outside this dialect. Unsupported syntax
is an error, with a file and line number. There are no includes or extensions.

Give aliases together in NAME, separated by comma and space. The first name must
match the title. For another installed name, add a source symlink as with
[poweroff.8.md](../cmd/reboot/poweroff.8.md).

## Build and check

```sh
make manpages FORM=playground
mandoc build/man/cmd/posture/posture.8
make man-lint
make _test/tools/mdoc.zig _test/mdoc
```

Generated pages live under `build/man/`; edit only the Markdown sources. The
compiler takes one UTF-8 file, bounded to 256 KiB, and writes a complete manual to
standard output only after parsing succeeds. The date comes from the source.
The same source produces the same bytes, without reading the clock or other files.
Roff control characters and macro names in input are escaped as data.

The rendering test compares posture, mount and su with their original handwritten
mdoc pages in `test/mdoc-pages/`, in ASCII and UTF-8 at 60, 78 and 100 columns.
It compares emphasis and spacing as well as text. When changing those manuals'
content, update their reference pages and inspect the rendered difference.
Markdown manual changes also participate in image release fingerprints and CI
path filters.
