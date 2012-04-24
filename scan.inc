<?php
require_once('helpers.inc');

function vulnscan_scan_form($form, &$form_state) {
    global $user;
    $groups = user_scannable_groups($user);
    $servers = array();
    $sites = get_all_sites_assoc();
    $win_servers = array();

    if (count($groups) == 0) {
        $form['vulnscan_nogroups'] = array(
            '#type' => 'markup',
            '#prefix' => '<div>',
            '#markup' => t('No scannable groups'),
            '#suffix' => '</div>',
        );

        return $form;
    }

    if (count($sites) == 0) {
        $form['vulnscan_nosites'] = array(
            '#type' => 'markup',
            '#prefix' => '<div>',
            '#markup' => t('No scannable sites'),
            '#suffix' => '</div>',
        );

        return $form;
    }

    foreach ($groups as $group) {
        foreach (get_all_servers_in_server_group_assoc($group) as $key => $value)
            $servers[$key] = $value;

        foreach (get_all_win_servers_in_server_group_assoc($group) as $key => $value)
            $win_servers[$key] = $value;
    }

    if (count($servers) == 0 || count($win_servers) == 0) {
        drupal_set_message(t('No available servers to scan. Please configure user to scan at least one BSD and one Windows server.'), 'error');

        $form['error'] = array(
            '#type' => 'markup',
            '#prefix' => '<div>',
            '#markup' => t('Access Denied'),
            '#suffix' => '</div>',
        );

        return $form;
    }

    $form['vulnscan_scan_servers'] = array(
        '#type' => 'fieldset',
        '#title' => t('Scan Individual Servers'),
    );

    $form['vulnscan_scan_servers']['servers'] = array(
        '#title' => t('BSD Servers'),
        '#type' => 'select',
        '#options' => $servers,
    );

    $form['vulnscan_scan_servers']['win_servers'] = array(
        '#title' => t('Windows Servers'),
        '#type' => 'select',
        '#options' => $win_servers,
    );

    $form['vulnscan_scan_host'] = array(
        '#type' => 'select',
        '#title' => t('Site to Scan'),
        '#options' => $sites,
    );

    $form['submit'] = array(
        '#type' => 'submit',
        '#value' => 'Run Scan',
    );

    return $form;
}

function vulnscan_scan_form_submit($form, &$form_state) {
    global $user;
    $site = $form_state['values']['vulnscan_scan_host'];

    if (isset($form_state['values']['servers']) && strlen($form_state['values']['servers'])
        && isset($form_state['values']['win_servers']) && strlen($form_state['values']['win_servers'])) {

        $server = $form_state['values']['servers'];
        $win_server = $form_state['values']['win_servers'];

        if (user_can_scan_server($user, $server) == false) {
            drupal_set_message(t('Invalid server: @server', array('@server' => $server)), 'error');
            return;
        }

        if (user_can_scan_win_server($user, $win_server) == false) {
            drupal_set_message(t('Invalid server: @server', array('@server' => $server)), 'error');
            return;
        }

        if (run_scan_on_server($site, $server, $win_server))
            drupal_set_message(t('Scanning @server in the background.', array('@server' => $server)));
    }
}
