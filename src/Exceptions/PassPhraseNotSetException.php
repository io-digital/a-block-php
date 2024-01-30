<?php

namespace IODigital\ABlockPHP\Exceptions;

use Illuminate\Http\Response;
use Exception;

class PassPhraseNotSetException extends Exception
{
    protected $code = Response::HTTP_BAD_REQUEST;
    protected $message = 'Pass phrase not set';
}
