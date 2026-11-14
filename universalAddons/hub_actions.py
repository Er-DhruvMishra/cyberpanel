"""Root-side action for the Universal Add-ons hub: which add-ons users may use."""
from universalAddons.access import save_policy_keys, user_modules


def set_user_access(values):
    policy = save_policy_keys(values)
    return {'user_modules': user_modules(policy)}


ACTIONS = {'set_user_access': set_user_access}
