<?php
// misp-config prepares the files Cake loads. The image's Config directory
// is a data volume, so it starts empty, and core.default.php ships Cake's
// published salt. This replaces that salt once and drops the auth plugins
// and the resque loader the image's own install removes.
$cfg = "/var/www/MISP/app/Config";
$core = $cfg . "/core.php";
$boot = $cfg . "/bootstrap.php";

$c = file_get_contents($core);
$published = "Rooraenietu8Eeyo<Qu2eeNfterd-dd+";
$publishedSeed = "395786739573056621429506834955";
if (str_contains($c, $published)) {
    $salt = rtrim(strtr(base64_encode(random_bytes(24)), "+/", "AB"), "=");
    $seed = "";
    for ($i = 0; $i < 30; $i++) {
        $seed .= random_int(0, 9);
    }
    $c = str_replace($published, $salt, $c);
    $c = str_replace($publishedSeed, $seed, $c);
    file_put_contents($core, $c);
}

$b = file_get_contents($boot);
$drop = [
    "CakePlugin::load('AadAuth');",
    "CakePlugin::load('CertAuth');",
    "CakePlugin::load('LdapAuth');",
    "CakePlugin::load('LinOTPAuth');",
    "CakePlugin::load('OidcAuth');",
    "CakePlugin::load('ShibbAuth');",
];
$n = str_replace($drop, "", $b);
$n = str_replace("\tCakePlugin::loadAll(array(\n\t\t'CakeResque' => array('bootstrap' => true)\n\t));\n", "", $n);
if ($n !== $b) {
    file_put_contents($boot, $n);
}
