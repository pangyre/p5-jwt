use inc::Module::Install;
all_from "lib/JWT.pm";

requires "Module::CPANfile";

cpanfile;

WriteAll;

__END__

 carton exec perl Makefile.PL

    rm -f META.yml ; perl Makefile.PL
