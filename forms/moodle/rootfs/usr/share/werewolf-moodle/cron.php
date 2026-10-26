<?php
// Load Moodle only after its installer, upgrade and cache refresh have finished.
// /run is fresh on boot; setup.php clears the mark on a service restart too.
if (@file_get_contents('/run/svc/moodle/ready') !== "ready\n") {
    fwrite(STDOUT, "moodle-cron: installation or upgrade is not ready; waiting\n");
    exit(0);
}

require '/usr/share/moodle/admin/cli/cron.php';
