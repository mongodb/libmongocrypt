include (FetchContent)

# Obtain Catch2 v3.1.0
FetchContent_Declare (Catch2
    URL "https://github.com/catchorg/Catch2/archive/refs/tags/v3.1.0.zip"
    )

FetchContent_MakeAvailable (Catch2)

# Import the module, used to define/discover tests automatically
include (Catch)
