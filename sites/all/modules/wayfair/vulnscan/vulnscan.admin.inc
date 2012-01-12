<?php

require_once('helpers.inc');

function vulnscan_admin_settings($form, &$form_state) {
    $servers = get_all_servers_assoc();

    /* Main settings */
    $form['vulnscan_skipfish_settings'] = array(
        '#type' => 'fieldset',
        '#title' => t('Skipfish Settings'),
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
    );

    $form['vulnscan_skipfish_settings']['skipfish_location'] = array(
        '#type' => 'textfield',
        '#title' => t('Skipfish Location'),
        '#default_value' => variable_get('vulnscan_skipfish_location', '/usr/local/bin/skipfish'),
        '#size' => 30,
    );

    /* Server settings */
    $form['vulnscan_server_settings'] = array(
        '#type' => 'fieldset',
        '#title' => 'Available Servers',
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
    );

    if (count($servers) > 0) {
        $form['vulnscan_server_settings']['servers'] = array(
            '#type' => 'select',
            '#title' => t('Existing Servers'),
            '#multiple' => TRUE,
            '#description' => 'Select one or more servers to delete upon saving the form.',
            '#options' => $servers,
        );
    }

    $form['vulnscan_server_settings']['new_server'] = array(
        '#type' => 'textfield',
        '#title' => t('Add a New Server'),
        '#size' => 30
    );

    $form['submit'] = array(
        '#type' => 'submit',
        '#value' => t('Save Settings'),
    );

    return $form;
}

function vulnscan_admin_settings_submit($form, &$form_state) {
    variable_set('vulnscan_skipfish_location', $form_state['values']['skipfish_location']);

    /* Save the new server */
    if (isset($form_state['values']['new_server']) && strlen($form_state['values']['new_server'])) {
        $name = strtoupper($form_state['values']['new_server']);
        $servers = get_all_servers_assoc();

        if (array_key_exists($name, $servers)) {
            form_set_error('new_server', t('Server @server already exists.', array('@server' => $name)));
        } else {
            db_insert('vulnscan_server')->fields(array(
                'name' => $name
            ))->execute();
        }
    }

    /* Delete selected servers */
    if (isset($form_state['values']['servers'])) {
        delete_servers(array_filter($form_state['values']['servers']));
    }
}
