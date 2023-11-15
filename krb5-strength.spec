%bcond_with	krb5		# build with MIT kerberos if asked

# Crypt::PBKDF2 isn't in base or EPEL on rhel8 so this won't work there frex
%bcond_with     history # build heimdal-history tool

Name:		krb5-strength
Version:	3.2
Release:	1%{?dist}
Summary:	Kerberos password strength checking plugin
Group:		System Environment/Daemons
License:	GPLv2+
Vendor:		Russ Allbery
URL:            https://www.eyrie.org/~eagle/software/%{name}/
Source0:	https://archives.eyrie.org/software/kerberos/%{name}-%{version}.tar.gz

%if %{with krb5}
BuildRequires: krb5-devel
%else
BuildRequires: heimdal-devel
BuildRequires: libcom_err-devel
BuildRequires: ncurses-devel
%endif
BuildRequires: sqlite-devel
BuildRequires: tinycdb-devel

Requires: perl(autodie)
Requires: perl(Getopt::Long)
Requires: sqlite
Requires: tinycdb
%if %{with krb5}
Requires: krb5-server
%else
Requires: heimdal-server
%endif
%if %{with history}
%package -n %{name}-history
Summary:	Kerberos password strength checking plugin history tool
Group:		System Environment/Daemons
Requires: %{name}
Requires: perl(autodie)
Requires: perl(Crypt::PBKDF2)
Requires: perl(DB_File::Lock)
Requires: perl(Getopt::Long::Descriptive)
Requires: perl(IPC::Run)
Requires: perl(JSON)
Requires: perl(Readonly)
%description -n %{name}-history
Heimdal password history tool for Kerberos password strength checking plugin
%endif

%description
Kerberos password strength checking plugin and program for Heimdal KDC

%prep
%setup -q

# in theory a system could have Heimdal and krb5
%build 
%if %{with krb5}
export PATH_KRB5_CONFIG=/usr/bin/krb5-config
%else
export PATH_KRB5_CONFIG=/usr/bin/heimdal-krb5-config
%endif
%configure
%make_build

%install
%make_install
%if !%{with history}
rm -f $RPM_BUILD_ROOT%{_bindir}/heimdal-history
rm -f $RPM_BUILD_ROOT%{_mandir}/man1/heimdal-history.*
%endif

%files
%defattr(-,root,root)
%license LICENSE
%doc README
%{_bindir}/heimdal-strength
%{_bindir}/krb5-strength-wordlist
%{_mandir}/man1/heimdal-strength.*
%{_mandir}/man1/krb5-strength-wordlist.*
%{_mandir}/man5
%{_libdir}/krb5/plugins/pwqual/strength.so
%{_libdir}/krb5/plugins/pwqual/strength.la

%if %{with history}
%files -n %{name}-history
%defattr(-,root,root)
%{_bindir}/heimdal-history
%{_mandir}/man1/heimdal-history.*
%endif

%changelog
* Wed Nov 15 2023 Daria Phoebe Brashear <dariaphoebe@auristor.com> 3.2-1
- Heimdal spec file
