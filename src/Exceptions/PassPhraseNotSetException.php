<?php

namespace IODigital\ABlockPHP\Exceptions;

use Illuminate\Http\Response;

class PassPhraseNotSetException extends ApplicationException
{
    public function status(): int
    {
        return Response::HTTP_BAD_REQUEST;
    }

    public function help(): string
    {
        return 'Please set the pass phrase using `setPassPhrase()`';
    }

    public function error(): string
    {
        return 'Pass phrase not set';
    }
}
