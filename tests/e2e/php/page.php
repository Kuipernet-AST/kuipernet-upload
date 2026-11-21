<?php
// A page WITHOUT any upload feature: it only reads a query parameter.
// The record shows what the PHP engine parsed anyway before this code ran.
require __DIR__ . '/record.php';
$q = $_GET['q'] ?? '';
mgus_record('page.php');
