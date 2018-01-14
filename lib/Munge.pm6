use NativeCall;

constant LIBMUNGE = ('munge', v2);

sub free(Pointer) is native {}

enum Munge::Opt <
    MUNGE_OPT_CIPHER_TYPE
    MUNGE_OPT_MAC_TYPE
    MUNGE_OPT_ZIP_TYPE
    MUNGE_OPT_REALM
    MUNGE_OPT_TTL
    MUNGE_OPT_ADDR4
    MUNGE_OPT_ENCODE_TIME
    MUNGE_OPT_DECODE_TIME
    MUNGE_OPT_SOCKET
    MUNGE_OPT_UID_RESTRICTION
    MUNGE_OPT_GID_RESTRICTION
>;

enum Munge::Cipher <
    MUNGE_CIPHER_NONE
    MUNGE_CIPHER_DEFAULT
    MUNGE_CIPHER_BLOWFISH
    MUNGE_CIPHER_CAST5
    MUNGE_CIPHER_AES128
    MUNGE_CIPHER_AES256
>;

enum Munge::MAC <
    MUNGE_MAC_NONE
    MUNGE_MAC_DEFAULT
    MUNGE_MAC_MD5
    MUNGE_MAC_SHA1
    MUNGE_MAC_RIPEMD160
    MUNGE_MAC_SHA256
    MUNGE_MAC_SHA512
>;

enum Munge::Zip <
    MUNGE_ZIP_NONE
    MUNGE_ZIP_DEFAULT
    MUNGE_ZIP_BZLIB
    MUNGE_ZIP_ZLIB
>;

constant \MUNGE_TTL_MAXIMUM := -1;
constant \MUNGE_TTL_DEFAULT := 0;

constant \MUNGE_UID_ANY := -1;
constant \MUNGE_GID_ANY := -1;

enum Munge::Error <
    EMUNGE_SUCCESS
    EMUNGE_SNAFU
    EMUNGE_BAD_ARG
    EMUNGE_BAD_LENGTH
    EMUNGE_OVERFLOW
    EMUNGE_NO_MEMORY
    EMUNGE_SOCKET
    EMUNGE_TIMEOUT
    EMUNGE_BAD_CRED
    EMUNGE_BAD_VERSION
    EMUNGE_BAD_CIPHER
    EMUNGE_BAD_MAC
    EMUNGE_BAD_ZIP
    EMUNGE_BAD_REALM
    EMUNGE_CRED_INVALID
    EMUNGE_CRED_EXPIRED
    EMUNGE_CRED_REWOUND
    EMUNGE_CRED_REPLAYED
    EMUNGE_CRED_UNAUTHORIZED
>;

class X::Munge::Error is Exception
{
    has Munge::Error $.code;

    sub munge_strerror(int32 --> Str) is native(LIBMUNGE) {}

    method message() { munge_strerror($!code) }
}

sub munge-check($code)
{
    die X::Munge::Error.new(code => Munge::Error($code)) if $code;
}

class Munge::Context is repr('CPointer')
{
    sub munge_ctx_create(--> Munge::Context) is native(LIBMUNGE) {}

    sub munge_ctx_destroy(Munge::Context)  is native(LIBMUNGE) {}

    sub munge_ctx_get_int32(Munge::Context, int32, int32 is rw --> int32)
        is native(LIBMUNGE) is symbol('munge_ctx_get') {}

    sub munge_ctx_set_int32(Munge::Context, int32, int32 --> int32)
        is native(LIBMUNGE) is symbol('munge_ctx_set') {}

    sub munge_ctx_get_int64(Munge::Context, int32, int64 is rw --> int32)
        is native(LIBMUNGE) is symbol('munge_ctx_get') {}

    sub munge_ctx_set_int64(Munge::Context, int32, int64 --> int32)
        is native(LIBMUNGE) is symbol('munge_ctx_set') {}

    sub munge_ctx_get_str(Munge::Context, int32, Pointer is rw --> int32)
        is native(LIBMUNGE) is symbol('munge_ctx_get') {}

    sub munge_ctx_set_str(Munge::Context, int32, Str --> int32)
        is native(LIBMUNGE) is symbol('munge_ctx_set') {}

    sub inet_ntoa(int64 --> Str) is native is symbol('inet_ntoa') {}

    method new { munge_ctx_create }

    method clone(--> Munge::Context)
        is native(LIBMUNGE) is symbol('munge_ctx_copy') {}

    method error(--> Str) is native(LIBMUNGE) is symbol('munge_ctx_strerror') {}

    method cipher(Munge::Cipher $cipher?)
    {
        my int32 $ciphertype;
        with $cipher
        {
            munge-check(munge_ctx_set_int32(self, MUNGE_OPT_CIPHER_TYPE, $_))
        }
        munge-check(munge_ctx_get_int32(self, MUNGE_OPT_CIPHER_TYPE,
                                        $ciphertype));
        Munge::Cipher($ciphertype)
    }

    method MAC(Munge::MAC $mac?)
    {
        my int32 $mactype;
        with $mac
        {
            munge-check(munge_ctx_set_int32(self, MUNGE_OPT_MAC_TYPE, $_))
        }
        munge-check(munge_ctx_get_int32(self, MUNGE_OPT_MAC_TYPE, $mactype));
        Munge::MAC($mactype)
    }

    method zip(Munge::Zip $zip?)
    {
        my int32 $ziptype;
        with $zip
        {
            munge-check(munge_ctx_set_int32(self, MUNGE_OPT_ZIP_TYPE, $_))
        }
        munge-check(munge_ctx_get_int32(self, MUNGE_OPT_ZIP_TYPE, $ziptype));
        Munge::Zip($ziptype)
    }

    method ttl(Int $seconds?)
    {
        my int32 $ttl;
        with $seconds
        {
            munge-check(munge_ctx_set_int32(self, MUNGE_OPT_TTL, $_))
        }
        munge-check(munge_ctx_get_int32(self, MUNGE_OPT_TTL, $ttl));
        $ttl
    }

    method addr4
    {
        my int64 $addr4;

        munge-check(munge_ctx_get_int64(self, MUNGE_OPT_ADDR4, $addr4));
        inet_ntoa($addr4)
    }

    method encode-time
    {
        my int64 $time;
        munge-check(munge_ctx_get_int64(self, MUNGE_OPT_ENCODE_TIME, $time));
        DateTime.new($time)
    }

    method decode-time
    {
        my int64 $time;
        munge-check(munge_ctx_get_int64(self, MUNGE_OPT_DECODE_TIME, $time));
        DateTime.new($time)
    }

    method socket(Str $local-domain-socket?)
    {
        my Pointer $p .= new;
        with $local-domain-socket
        {
            munge-check: munge_ctx_set_str(self, MUNGE_OPT_SOCKET,
                                           $local-domain-socket)
        }
        munge-check: munge_ctx_get_str(self, MUNGE_OPT_SOCKET, $p);
        nativecast(Str, $p)
    }

    method uid-restriction(Int $uid?)
    {
        my int32 $uid_t;
        with $uid
        {
            munge-check(munge_ctx_set_int32(self, MUNGE_OPT_UID_RESTRICTION,
                                            $uid))
        }
        munge-check(munge_ctx_get_int32(self, MUNGE_OPT_UID_RESTRICTION,
                                        $uid_t));
        $uid_t
    }

    method gid-restriction(Int $gid?)
    {
        my int32 $gid_t;
        with $gid
        {
            munge-check(munge_ctx_set_int32(self, MUNGE_OPT_GID_RESTRICTION,
                                            $gid))
        }
        munge-check(munge_ctx_get_int32(self, MUNGE_OPT_GID_RESTRICTION,
                                        $gid_t));
        $gid_t
    }

    submethod DESTROY { munge_ctx_destroy(self) }
}

class Munge
{
    has Munge::Context $.context handles<error cipher MAC zip ttl addr4 socket
                                         encode-time decode-time
                                         uid-restriction gid-restriction>;
    has int32 $.uid;
    has int32 $.gid;

    sub munge_encode(Pointer is rw, Munge::Context, Blob, int32 --> int32)
        is native(LIBMUNGE) {}

    sub munge_decode(Str, Munge::Context, Pointer is rw, int32 is rw,
                     int32 is rw, int32 is rw --> int32) is native(LIBMUNGE) {}

    submethod TWEAK(:$cipher, :$MAC, :$zip, :$ttl, :$socket,
                    :$uid-restriction, :$gid-restriction)
    {
        $!context .= new;
        $!context.ttl($_) with $ttl;
        $!context.socket($_) with $socket;
        $!context.uid-restriction($_) with $uid-restriction;
        $!context.gid-restriction($_) with $gid-restriction;

        given $cipher
        {
            when Munge::Cipher { $!context.cipher($_) }
            when Str:D
            {
                $!context.cipher(Munge::Cipher::{"MUNGE_CIPHER_$_"}
                                 // die "Unknown Cipher $_")
            }
        }

        given $MAC
        {
            when Munge::MAC { $!context.MAC($_) }
            when Str:D
            {
                $!context.MAC(Munge::MAC::{"MUNGE_MAC_$_"}
                              // die "Unknown Cipher $_")
            }
        }

        given $zip
        {
            when Munge::Zip { $!context.zip($_) }
            when Str:D
            {
                $!context.zip(Munge::Zip::{"MUNGE_ZIP_$_"}
                              // die "Unknown Zip $_")
            }
        }
    }

    multi method encode(Str $str)
    {
        samewith $str.encode
    }

    multi method encode(Blob $buf?)
    {
        my Pointer $cred .= new;
        LEAVE free($_);
        munge-check(munge_encode($cred, $!context, $buf,
                                 $buf ?? $buf.bytes !! 0));
        nativecast(Str, $cred)
    }

    method decode-buf(Str $cred)
    {
        my int32 $len;
        my Pointer $ptr .= new;
        LEAVE free($_);
        munge-check(munge_decode($cred, $!context, $ptr, $len, $!uid, $!gid));
        buf8.new(nativecast(CArray[uint8], $ptr)[0 ..^ $len])
    }

    method decode(Str $cred) { $.decode-buf($cred).decode }
}
