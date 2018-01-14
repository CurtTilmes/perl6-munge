use Test;
use Test::When <extended>;

use Munge;

plan 3;

subtest 'Defaults',
{
    plan 7;

    ok my $m = Munge.new, 'new';

    is $m.cipher, MUNGE_CIPHER_DEFAULT, 'cipher default';

    is $m.MAC, MUNGE_MAC_DEFAULT, 'MAC default';

    is $m.zip, MUNGE_ZIP_DEFAULT, 'Zip default';

    is $m.ttl, MUNGE_TTL_DEFAULT, 'TTL default';

    is $m.uid-restriction, MUNGE_UID_ANY, 'UID default';

    is $m.gid-restriction, MUNGE_GID_ANY, 'GID default';
}

subtest 'Set by enumeration',
{
    plan 7;

    ok my $m = Munge.new(cipher => MUNGE_CIPHER_BLOWFISH,
                         MAC => MUNGE_MAC_SHA512,
                         zip => MUNGE_ZIP_BZLIB,
                         ttl => 3000,
                         uid-restriction => 123,
                         gid-restriction => 456),
        'new';

    is $m.cipher, MUNGE_CIPHER_BLOWFISH, 'cipher set';

    is $m.MAC, MUNGE_MAC_SHA512, 'MAC set';

    is $m.zip, MUNGE_ZIP_BZLIB, 'Zip set';

    is $m.ttl, 3000, 'ttl set';

    is $m.uid-restriction, 123, 'uid restriction set';

    is $m.gid-restriction, 456, 'gid restriction set';
}

subtest 'Set by string',
{
    plan 7;

    ok my $m = Munge.new(cipher => 'BLOWFISH',
                         MAC => 'SHA512',
                         zip => 'BZLIB',
                         ttl => 3000,
                         uid-restriction => 123,
                         gid-restriction => 456),
        'new';

    is $m.cipher, MUNGE_CIPHER_BLOWFISH, 'cipher set';

    is $m.MAC, MUNGE_MAC_SHA512, 'MAC set';

    is $m.zip, MUNGE_ZIP_BZLIB, 'Zip set';

    is $m.ttl, 3000, 'ttl set';

    is $m.uid-restriction, 123, 'uid restriction set';

    is $m.gid-restriction, 456, 'gid restriction set';
}

done-testing;
