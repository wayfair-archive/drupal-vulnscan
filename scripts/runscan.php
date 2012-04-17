#!/usr/local/bin/php

<?php
/*
 * Script Arguments:
 *      1) -s <scanner>: The path to the scanner to be run
 *      2) -t <email>: Email address to notify when scan is completed
 *      3) -f <email>: Email address from which the email will come
 *      4) -l <link>: Link to the scan
 */

function is_option_set($options, $option) {
    if (isset($options[$option]) && strlen($options[$option]))
        return true;

    return false;
}

function run_scan($options) {
    $output = array();

    $run = $options['s'];
    exec($run);

    if (is_option_set($options, 't') && is_option_set($options, 'f') && is_option_set($options, 'l'))
        email_user($options);
}

function email_user($options) {
    $body = "Scan completed. Visit <a href=\"{$options['l']}\">{$options['l']}</a> for the results.";
    $headers = "From: {$options['f']}\r\n";

    mail($options['t'], "Scan completed", $body, $headers);
}

$options = getopt("s:f:t:l:");

/* Make sure the necessary options are set */
if (is_option_set($options, 's') == false)
    exit(1);

run_scan($options);
?>
