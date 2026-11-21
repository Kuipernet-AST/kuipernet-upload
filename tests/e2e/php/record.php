<?php
// Test backend only: records what PHP made of the request it received.
// PHP has already parsed the multipart body before this file runs.

function mgus_collect($name, $size, $error, $tmp, array &$out): void
{
    if (is_array($name)) {
        foreach ($name as $k => $v) {
            mgus_collect($v, $size[$k], $error[$k], $tmp[$k], $out);
        }
        return;
    }
    $out[] = [
        'size'   => $size,
        'error'  => $error,
        'sha256' => ($error === UPLOAD_ERR_OK) ? hash_file('sha256', $tmp) : null,
    ];
}

function mgus_record(string $script): void
{
    $files = [];
    foreach ($_FILES as $e) {
        mgus_collect($e['name'], $e['size'], $e['error'], $e['tmp_name'], $files);
    }

    $fields = 0;
    $max_field = 0;
    array_walk_recursive($_POST, function ($v) use (&$fields, &$max_field) {
        $fields++;
        $max_field = max($max_field, strlen((string) $v));
    });

    $sizes = array_column($files, 'size');
    $rec = [
        'backend'        => 'php-fpm',
        'script'         => $script,
        'test_id'        => $_SERVER['HTTP_X_TEST_ID'] ?? '',
        'content_length' => (int) ($_SERVER['CONTENT_LENGTH'] ?? 0),
        'files'          => count($files),
        'fields'         => $fields,
        'max_file_bytes' => $sizes ? max($sizes) : 0,
        'max_field_bytes'=> $max_field,
        'file_list'      => $files,
        'top_level_file_keys'  => count($_FILES),
        'top_level_field_keys' => count($_POST),
    ];

    $line = json_encode($rec) . "\n";
    file_put_contents(getenv('MGUS_LOG'), $line, FILE_APPEND | LOCK_EX);

    header('Content-Type: application/json');
    echo $line;
}
