<?php declare(strict_types=1);

namespace Sunkan\AwsAuthPolicy;

interface ResourcePolicy
{
    public function configurePolicy(AuthPolicy $policy): void;
}
