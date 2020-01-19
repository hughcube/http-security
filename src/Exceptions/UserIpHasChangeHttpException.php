<?php

namespace HughCube\HttpSecurity\Exceptions;

use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class UserAgentHasChangeHttpException extends BadRequestHttpException implements Exception
{
}
