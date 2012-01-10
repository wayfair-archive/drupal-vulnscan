<?php

function vulnscan_scan_form($form, &$form_state) {
    $form['vulnscan_scan'] = array(
        '#type' => 'markup',
        '#prefix' => '<div>',
        '#markup' => t('Under Construction. Good news - you can run scans!'),
        '#suffix' => '</div>',
    );

    return $form;
}
