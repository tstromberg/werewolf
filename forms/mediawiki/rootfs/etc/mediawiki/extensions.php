<?php
/**
 * extensions.php: the skins and extensions of the mediawiki form, all from
 * MediaWiki's own tarball. LocalSettings.php loads them, and setup.php
 * names them to the installer, which makes their tables.
 *
 * Left out, as each runs a program or reaches another server: Math
 * (Wikimedia's renderer), SyntaxHighlight (pygmentize), Scribunto (a Lua
 * program), PdfHandler (Ghostscript), SpamBlacklist (Wikimedia's lists);
 * and Echo and those on it, as the form sends no mail.
 */
return [
	'skins' => [ 'Vector', 'MonoBook', 'Timeless' ],
	'extensions' => [
		'CategoryTree',
		'Cite',
		'CiteThisPage',
		'CodeEditor',
		'ImageMap',
		'InputBox',
		'Interwiki',
		'MultimediaViewer',
		'Nuke',
		'OATHAuth',
		'ParserFunctions',
		'Poem',
		'ReplaceText',
		'SecureLinkFixer',
		'TemplateData',
		'VisualEditor',
		'WikiEditor',
	],
];
