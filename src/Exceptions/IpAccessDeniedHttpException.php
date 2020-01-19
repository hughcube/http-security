<?php

namespace HughCube\HttpSecurity\Exceptions;

use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class IpAccessDeniedHttpException extends AccessDeniedHttpException implements Exception
{
}
