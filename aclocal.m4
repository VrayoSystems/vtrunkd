dnl Test files
AC_DEFUN( AC_TEST_FILES,
[
    ac_file_found=yes
    for f in $1; do
	if test ! -f $2/$f; then
    	   ac_file_found=no
	   break;
	fi
    done

    if test "$ac_file_found" = "yes" ; then
	ifelse([$3], , :,[$3])
    else
	ifelse([$4], , :,[$4])
    fi
])

dnl Search for headers, add path to CPPFLAGS if found 
AC_DEFUN( AC_SEARCH_HEADERS, 
[
    AC_MSG_CHECKING("for $1") 
    ac_hdr_found=no
    for p in $2; do
	if test -n "$p"; then
	  dir="$p"
	else
	  dir="/usr/include"
	fi
	AC_TEST_FILES($1, $dir, 
	    [ 
     	       ac_hdr_found=yes
	       break
	    ]
	)
    done 
    if test "$ac_hdr_found" = "yes" ; then
	if test -n "$p"; then
	  CPPFLAGS="$CPPFLAGS -I$p"
	fi
        AC_MSG_RESULT( [($dir) yes] ) 
	ifelse([$3], , :,[$3])
    else
        AC_MSG_RESULT("no") 
	ifelse([$4], , :,[$4])
    fi
])


dnl Create links to all files($1) in the directory($2)
AC_DEFUN( AC_LINK_DIR, 
[
    for i in $1; do
      if test -f $2/$i -a ! -f $i; then
         AC_MSG_RESULT(linking $2/$i  to  $i)
         ln -f -s $2/$i $i
      fi
    done 
])

dnl Create driver and protocol links
dnl $1 - drivers list, $2 - os dir
AC_DEFUN( AC_LINK_DRV, 
[
    AC_MSG_RESULT( creating driver and protocol links ... )

    if test "$2" != ""; then
       AC_LINK_DIR($1, $2)
    fi
    AC_LINK_DIR($1, generic)
])
