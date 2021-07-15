# Aws Auth Policy

[![Latest Version on Packagist](https://img.shields.io/packagist/v/sunkan/aws-auth-policy.svg)](https://packagist.org/packages/sunkan/aws-auth-policy)
[![Software License](https://img.shields.io/github/license/sunkan/aws-auth-policy.svg)](LICENSE)
[![Build Status](https://github.com/sunkan/aws-auth-policy/actions/workflows/unit-test.yml/badge.svg)](https://github.com/sunkan/aws-auth-policy/actions/workflows/unit-test.yml)
[![Coverage Status](https://coveralls.io/repos/github/sunkan/aws-auth-policy/badge.svg?branch=main)](https://coveralls.io/github/sunkan/aws-auth-policy?branch=main)

## Installation

```
$ composer require sunkan/aws-auth-policy
```

## Usage

```php
use Sunkan\AwsAuthPolicy\AuthPolicy;

$policy = new AuthPolicy(
    'me',
    '50505050',
    [
        'region' => 'eu-west-1',
        'stage' => 'prod',
    ],
);

$policy->allowAll();

echo json_encode($policy->build());
```

## Usage with Bref

```php
use Bref\Context\Context;
use Bref\Event\Handler;
use Sunkan\AwsAuthPolicy\AuthPolicy;

final class AuthorizerAction implements Handler
{
    public function handle($event, Context $context)
    {
        $policy = AuthPolicy::fromMethodArn($event['methodArn']);
        // validate $event['authorizationToken']
        if ($validToken) {
            $policy->allowAll();
        }
        else {
            $policy->denyAll();
        }

        return $policy;
    }
}
```
