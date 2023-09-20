<?php

namespace IODigital\ABlockPHP\Exceptions;

use Illuminate\Http\Response;

class ActiveWalletNotSetException extends ApplicationException
{
    public function status(): int
    {
        return Response::HTTP_BAD_REQUEST;
    }

    public function help(): string
    {
        return 'Please set the active wallet';
    }

    public function error(): string
    {
        return 'Active wallet not set';
    }
}
