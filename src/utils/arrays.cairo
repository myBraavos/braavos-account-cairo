use core::dict::Felt252DictTrait;
use traits::{Into, TryInto};

fn span_to_dict<T, impl IntoFelt: Into<T, felt252>, impl Copy: Copy<T>>(
    mut arr: Span<T>, assert_unique: bool,
) -> Felt252Dict<bool> {
    let mut guid_set: Felt252Dict<bool> = Default::default();
    loop {
        match arr.pop_front() {
            Option::Some(guid) => {
                assert(!assert_unique || !guid_set.get((*guid).into()), 'DUPLICATE_VALUE');
                guid_set.insert((*guid).into(), true);
            },
            Option::None => { break; },
        };
    }
    guid_set
}
