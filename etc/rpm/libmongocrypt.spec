Name: libmongocrypt
Prefix: /usr
Version: %{dynamic_version}
Release: %{dynamic_release}%{?dist}
Summary: library to perform field-level encryption
License: Apache License 2.0
URL: https://github.com/mongodb/libmongocrypt
Group: Development/Libraries
Requires: libmongocrypt-devel = %{version}, libmongocrypt-libs = %{version}

Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
libmongocrypt facilitates the encryption and decryption, at the field
level, of data stored in MongoDB.

%package devel
Summary: library to perform field-level encryption - dev files
Group: Development/Libraries
Requires: libmongocrypt-libs = %{version}

%description devel
 libmongocrypt facilitates the encryption and decryption, at the field
 level, of data stored in MongoDB.
 .
 This package contains the libmongocrypt and libkms_message development
 headers and libraries.

%package libs
Summary: library to perform field-level encryption - runtime files
Group: Development/Libraries

%description libs
 This package contains the libmongocrypt and libkms_message runtime
 libraries.

%prep
%setup

%build

%install
mkdir -p $RPM_BUILD_ROOT/usr
cp -rv lib* $RPM_BUILD_ROOT/usr
cp -rv include $RPM_BUILD_ROOT/usr


%clean
rm -rf $RPM_BUILD_ROOT

%files

%files devel
%{_includedir}/*
%{_prefix}/lib64/*.a
%{_prefix}/lib64/lib*.so
%{_prefix}/lib64/pkgconfig/*
%{_prefix}/lib/*.a
%{_prefix}/lib/lib*.so
%{_prefix}/lib/cmake/*
%{_prefix}/lib/pkgconfig/*

%files libs
%{_prefix}/lib64/lib*.so.*
%{_prefix}/lib/lib*.so.*

%changelog
* Tue Aug 06 2019 Roberto C. Sanchez <roberto@connexer.com>  
- Initial release
