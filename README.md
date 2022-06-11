# caliban-schema-gen-failure
To showcase the failed `Schema.gen`

The compilation barely passes. Everything seemed normal. Once you uncomment more fields from `Mutations`, the compiler eventually gives up.

# fix (work-around)

Try separate your API into smaller ones and combine them by `|+|`. This way there's less burden on `Schema.gen`.
