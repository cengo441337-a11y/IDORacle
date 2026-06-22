"""Declarative authorization schema + equivalence-class partition (weeks 4-6).

An endpoint's object space is partitioned into AUTHORIZATION-EQUIVALENCE CLASSES:
two object refs share a class iff, for the fixed principal pair (A, B), they have
the same typed shape (object type, ownership relation to A and B, declared
visibility/lifecycle state) and therefore the same access-control decision.
Coverage (weeks 7-12) is defined over THIS partition - not over raw ids and not
over code paths, which is what answers "code coverage != vuln coverage".

The schema also declares the EXPECTED decision per class. That is what turns the
oracle's raw "B's write persisted" observation into a SOUND bug verdict: a
persisted B-write is a bug only on a class whose policy DENIES B. A legitimately
shared object that B may write is NOT a bug even though the canary changes - this
is the policy-awareness that keeps the oracle sound once any sharing model exists
(v1/v2 silently assumed owner-only-write).
"""

from dataclasses import dataclass
from itertools import product

# Relation of the object to the fixed principal pair (A, B).
OWNERSHIP = ("A_owns", "B_owns", "other_owns")


@dataclass(frozen=True)
class AuthzClass:
    obj_type: str
    ownership: str        # one of OWNERSHIP
    shared: bool          # declared visibility state

    @property
    def id(self) -> str:
        return f"{self.obj_type}|own={self.ownership}|shared={int(self.shared)}"


@dataclass
class EndpointSchema:
    """A tester-declared, finite typed schema for one endpoint.

    Finiteness is load-bearing: the certificate is conditional on this declaration.
    `shared_states` enumerates the declared visibility states; `b_write_allowed`
    is the declared policy whose violation IS the bug.
    """
    obj_type: str = "note"
    shared_states: tuple = (False, True)

    def b_write_allowed(self, cls: AuthzClass) -> bool:
        # Declared policy: B may write iff B owns the object OR it is shared.
        return cls.ownership == "B_owns" or cls.shared

    def enumerate_classes(self):
        """The TRUE, complete class set for (A, B) under this declared schema."""
        return [AuthzClass(self.obj_type, own, sh)
                for own, sh in product(OWNERSHIP, self.shared_states)]

    def plantable_classes(self):
        """Classes the tester can instantiate by creating as A -> exactly A_owns.
        Everything else is pre-existing -> not online-classifiable (the blindness)."""
        return [c for c in self.enumerate_classes() if c.ownership == "A_owns"]
