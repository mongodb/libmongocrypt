
configure_file(cs.sln cs.sln COPYONLY)

configure_file(MongoDB.Crypt/MongoDB.Crypt.csproj MongoDB.Crypt/MongoDB.Crypt.csproj COPYONLY)
configure_file(MongoDB.Crypt/Package.include.template.csproj MongoDB.Crypt/Package.csproj.include)

configure_file(MongoDB.Crypt.Test/MongoDB.Crypt.Test.csproj MongoDB.Crypt.Test/MongoDB.Crypt.Test.csproj COPYONLY)
configure_file(MongoDB.Crypt.Test/Package.include.template.csproj MongoDB.Crypt.Test/Package.csproj.include)

configure_file(MongoDB.Crypt.Test/MongoDB.Crypt.Test.csproj MongoDB.Crypt.Test32/MongoDB.Crypt.Test32.csproj COPYONLY)
configure_file(MongoDB.Crypt.Test/Package.include.template.csproj MongoDB.Crypt.Test32/Package.csproj.include)

configure_file(MongoDB.Crypt.Example/MongoDB.Crypt.Example.csproj MongoDB.Crypt.Example/MongoDB.Crypt.Example.csproj COPYONLY)
configure_file(MongoDB.Crypt.Example/Package.include.template.csproj MongoDB.Crypt.Example/Package.csproj.include)


