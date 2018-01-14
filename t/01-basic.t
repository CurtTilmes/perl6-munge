use Test;
use Test::When <extended>;

use Munge;

plan 3;

ok my $m = Munge.new, 'new';

ok my $encoding = $m.encode('this'), 'encode';

is $m.decode($encoding), 'this', 'decode';

done-testing;
