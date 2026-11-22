#!/bin/sh

if [ "${PWD##*/}" != "language" ]
then
	echo "Please run this script in the language/ subfolder of an warden source tree."
	exit 1
fi

# truncate
: > warden.pot

# find .cpp, .h, and .conf files
# exclude docs and third party modules
# run xgettext on found files
find ../ \
	! -path '../docs/*' \
	-a ! -path '../modules/third/*' \
	-a ! -path '../run/*' \
	-a ! -path '../vendor/*' \
	-a \( -name '*.cpp' \
		-o -name '*.h' \
		-o -name '*.conf' \
	\) \
	-print0 | sort -z | xargs -0 -I {} \
		xgettext \
			--language=C++ \
			--default-domain=Warden \
			--join-existing \
			--output=warden.pot \
			--from-code=utf-8 \
			--keyword \
			--keyword=_ \
			--keyword=N_:1,2 \
			{}

for f in *.po
do
	echo "Merging $f"
	msgmerge \
		--add-location=file \
		--no-wrap \
		--sort-output \
		--update \
		--verbose \
		"${f}" \
		"${f%%.*}.pot"
done

rm -f -- *~
