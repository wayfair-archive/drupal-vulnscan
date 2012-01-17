<?php

require_once('helpers.inc');

function vulnscan_list_scans_form($form, &$form_state) {
    global $user;
    $others = false;

    if (user_access('view others scans'))
        $others = true;

    $scans = list_scans($user, $others);

    $markup = '<ul>';
    foreach ($scans as $server => $server_scans) {
        $markup .= '<li>' . t($server) . '';
        $markup .= '<ul>';

        foreach ($server_scans as $scan => $location) {
            $markup .= '<li><a href="' . $location . '">' . t($scan) . '</a></li>';
        }

        $markup .= '</ul></li>';
    }

    $markup .= '</li></ul>';

    $form['vulnscan_scans'] = array(
        '#type' => 'markup',
        '#prefix' => '<div>',
        '#markup' => $markup,
        '#suffix' => '</div>',
    );

    return $form;
}
