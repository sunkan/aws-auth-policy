<?php declare(strict_types=1);

namespace Tests\Stub;

use Sunkan\AwsAuthPolicy\AuthPolicy;
use Sunkan\AwsAuthPolicy\ResourcePolicy;

final class StubResourcePolicy implements ResourcePolicy
{

    public function configurePolicy(AuthPolicy $policy): void
    {
        $policy->allow(AuthPolicy::GET, '/test/path');
    }
}
