<?php

namespace IODigital\ABlockPHP\Exceptions;

use Illuminate\Http\Response;

class KeypairNotDecryptedException extends ApplicationException
{
    public function status(): int
    {
        return Response::HTTP_BAD_REQUEST;
    }

    public function help(): string
    {
        return 'Ensure you have the correct pass phrase set';
    }

    public function error(): string
    {
        return 'Could not decrypt keypair';
    }
}
