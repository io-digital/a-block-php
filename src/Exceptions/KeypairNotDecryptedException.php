<?php

namespace IODigital\ABlockPHP\Exceptions;

use Illuminate\Http\Response;
use Exception;

class KeypairNotDecryptedException extends Exception
{
    protected $code = Response::HTTP_BAD_REQUEST;
    protected $message = 'Could not decrypt keypair';
}
