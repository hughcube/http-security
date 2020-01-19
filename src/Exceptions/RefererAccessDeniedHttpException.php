<?php

namespace HughCube\HttpSecurity\Exceptions;

use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class refererHotlinkingHttpException extends AccessDeniedHttpException implements Exception
{
}
