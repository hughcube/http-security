<?php

namespace HughCube\HttpSecurity\Exceptions;

use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class ClientIpHasChangeHttpException extends AccessDeniedHttpException implements Exception
{
}
