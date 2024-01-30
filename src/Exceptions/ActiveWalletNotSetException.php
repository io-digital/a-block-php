<?php

namespace IODigital\ABlockPHP\Exceptions;

use Illuminate\Http\Response;
use Exception;

class ActiveWalletNotSetException extends Exception
{
    protected $code = Response::HTTP_BAD_REQUEST;
    protected $message = 'Active wallet not set';
}
