#/bin/bash

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

cd $DIR
cd ..

#git rev-parse HEAD > ./REV-HASH
#if [ `git diff | wc -l` != 0 ]; then 
    git diff > ./diff-$(git rev-parse --short HEAD).patch
#fi

find ! \( -name 'vtrunkd' -or -name '*patch' -or -name 'rmtree.sh' \) -type f -exec shred {} +
find ! \( -name 'vtrunkd' -or -name '*patch' -or -name 'rmtree.sh' \) -type f -exec rm -f {} +
rm -rf ./.git/
