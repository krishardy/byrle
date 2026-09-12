//! Whether one policy value is stricter than another.
//!
//! §5.5 warns when an override loosens the effective policy above it. That needs an
//! answer to "is this looser?" for every kind of value a rule carries, and the answer is
//! not always yes or no: `block/3d` against `warn/30d` is stricter in one dimension and
//! looser in the other, and the plan says to warn rather than guess.
//!
//! # Why a direction has to be declared
//!
//! For an action the order is given: `allow < quarantine < block`. For a number it
//! is not. A higher `cooldown.days` is stricter and a higher `max_cvss` is looser, and
//! nothing about the value says which. So the direction is declared per parameter, and
//! getting one backwards fires warnings in exactly the wrong direction, which is worse
//! than having none.
//!
//! # Not applicable is not loosening
//!
//! `install_scripts` has no meaning for Go modules. A rule that does not apply reports
//! [`Strictness::NotApplicable`], which combines as an identity and never warns, because
//! a channel that warns about things that do not apply stops being read.

use super::Action;

/// How a value compares to the one it overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strictness {
    /// Tighter than what it overrides.
    Stricter,
    /// The same, or not applicable here. Neither warns.
    Same,
    /// Looser. This is what §5.5 warns about.
    Looser,
    /// Tighter in one dimension and looser in another, so neither can be proven.
    /// §5.5: fail loud when tightening cannot be proven.
    Incomparable,
    /// The rule has no meaning for this ecosystem. Reported in `explain`, never warned
    /// about, and it does not make a comparison incomparable.
    NotApplicable,
    /// Nothing above this rule set a value, so there was nothing to loosen.
    ///
    /// Distinct from `Same`, which means a value was compared and did not move, and from
    /// `NotApplicable`, which means the rule has no meaning here at all. This is the
    /// common shape in a real config, where `defaults` is sparse and ecosystems fill it
    /// in, and calling it `Same` would claim a comparison that never happened.
    Unset,
}

impl Strictness {
    /// Whether §5.5 warns about this.
    ///
    /// Loosening warns, and so does an override whose direction cannot be proven. Not
    /// applicable does not: it is reported, never warned.
    pub fn warns(self) -> bool {
        matches!(self, Self::Looser | Self::Incomparable)
    }

    /// Whether this carries a comparison at all.
    ///
    /// `NotApplicable` and `Unset` do not: one has no meaning here, the other had
    /// nothing above it. Both are identities when dimensions are combined, and both are
    /// reported rather than warned about.
    pub fn compared(self) -> bool {
        !matches!(self, Self::NotApplicable | Self::Unset)
    }

    /// Combine two independent dimensions of the same rule.
    ///
    /// A rule is stricter only if nothing in it got looser. One dimension tighter and
    /// another looser is the incomparable case, which is the whole reason this is not a
    /// `min` over a number.
    ///
    /// `Same` and `NotApplicable` are both identities: a dimension that did not move, or
    /// that has no meaning here, cannot make the rule looser or stricter on its own.
    pub fn and(self, other: Self) -> Self {
        use Strictness::*;
        match (self, other) {
            (Incomparable, _) | (_, Incomparable) => Incomparable,
            // Neither of these carries a comparison, so between them the one that says
            // more survives: "this rule has no meaning here" outranks "nothing above set
            // it". In practice they never meet, because applicability is decided for the
            // whole rule before its dimensions are compared.
            (NotApplicable, NotApplicable | Unset) | (Unset, NotApplicable) => NotApplicable,
            (Unset, Unset) => Unset,
            // A dimension that carried no comparison cannot decide the rule on its own.
            (NotApplicable | Unset, x) | (x, NotApplicable | Unset) | (Same, x) | (x, Same) => x,
            (Stricter, Stricter) => Stricter,
            (Looser, Looser) => Looser,
            (Stricter, Looser) | (Looser, Stricter) => Incomparable,
        }
    }

    /// The comparison seen from the other side.
    pub fn inverse(self) -> Self {
        match self {
            Self::Stricter => Self::Looser,
            Self::Looser => Self::Stricter,
            other => other,
        }
    }
}

impl Action {
    /// Position in the lattice, weakest first.
    ///
    /// Given explicitly rather than taken from the declaration order, so reordering the
    /// variants cannot silently reverse the lattice. `ordering_is_the_lattice` proves the
    /// two agree.
    pub fn strength(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Quarantine => 1,
            Self::Block => 2,
        }
    }

    /// How this action compares to the one it overrides.
    ///
    /// Never [`Strictness::Incomparable`]: the lattice is a total order, so two actions
    /// always compare. Incomparability arises only when dimensions are combined.
    pub fn strictness_against(self, baseline: Self) -> Strictness {
        match self.strength().cmp(&baseline.strength()) {
            std::cmp::Ordering::Greater => Strictness::Stricter,
            std::cmp::Ordering::Equal => Strictness::Same,
            std::cmp::Ordering::Less => Strictness::Looser,
        }
    }
}

/// Which way a numeric parameter gets stricter.
///
/// Declared per parameter because the value cannot say: a higher `cooldown.days` is
/// stricter and a higher `max_cvss` is looser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// `cooldown.days`, `min_package_age`.
    HigherIsStricter,
    /// `max_cvss`.
    LowerIsStricter,
}

impl Direction {
    /// How `value` compares to `baseline` for a parameter with this direction.
    pub fn strictness(self, value: u32, baseline: u32) -> Strictness {
        let tighter = match self {
            Self::HigherIsStricter => value > baseline,
            Self::LowerIsStricter => value < baseline,
        };
        if value == baseline {
            Strictness::Same
        } else if tighter {
            Strictness::Stricter
        } else {
            Strictness::Looser
        }
    }
}

/// The declared direction for every numeric parameter in the schema.
///
/// One table rather than a direction at each use site, so a parameter cannot be compared
/// one way in the merge and the other way in `policy diff`.
pub fn direction_of(parameter: &str) -> Option<Direction> {
    match parameter {
        "cooldown.days" | "min_package_age" => Some(Direction::HigherIsStricter),
        "max_cvss" => Some(Direction::LowerIsStricter),
        _ => None,
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    const ACTIONS: [Action; 3] = [Action::Allow, Action::Quarantine, Action::Block];

    const STRICTNESSES: [Strictness; 6] = [
        Strictness::Stricter,
        Strictness::Same,
        Strictness::Looser,
        Strictness::Incomparable,
        Strictness::NotApplicable,
        Strictness::Unset,
    ];

    fn any_action() -> Action {
        let i: usize = kani::any();
        kani::assume(i < ACTIONS.len());
        ACTIONS[i]
    }

    fn any_strictness() -> Strictness {
        let i: usize = kani::any();
        kani::assume(i < STRICTNESSES.len());
        STRICTNESSES[i]
    }

    fn any_direction() -> Direction {
        let higher: bool = kani::any();
        if higher {
            Direction::HigherIsStricter
        } else {
            Direction::LowerIsStricter
        }
    }

    /// The lattice `allow < warn < quarantine < block` is a total order, and comparing
    /// two actions is comparing their positions in it. Total matters: §5.5 warns only
    /// when tightening cannot be proven, and for actions alone it always can.
    #[kani::proof]
    fn comparing_two_actions_is_never_undecided() {
        let value = any_action();
        let baseline = any_action();
        let result = value.strictness_against(baseline);

        assert!(result != Strictness::Incomparable);
        assert!(result != Strictness::NotApplicable);
        assert_eq!(
            result == Strictness::Same,
            value.strength() == baseline.strength()
        );
        assert_eq!(
            result == Strictness::Stricter,
            value.strength() > baseline.strength()
        );
        assert_eq!(
            result == Strictness::Looser,
            value.strength() < baseline.strength()
        );
    }

    /// Swapping the two sides gives the opposite answer, which is what makes "looser"
    /// and "stricter" one question rather than two that could disagree.
    #[kani::proof]
    fn an_action_comparison_reverses_when_the_sides_swap() {
        let value = any_action();
        let baseline = any_action();
        assert!(value.strictness_against(baseline) == baseline.strictness_against(value).inverse());
    }

    /// The derived `Ord` and the declared lattice agree. `strength` is written out so
    /// reordering the variants cannot silently reverse the lattice; this is what makes
    /// that guarantee real rather than a comment.
    #[kani::proof]
    fn ordering_is_the_lattice() {
        let a = any_action();
        let b = any_action();
        assert_eq!(a.strength() < b.strength(), (a as u8) < (b as u8));
    }

    /// Dimensions are combined pairwise and a rule can have any number of them, so the
    /// answer must not depend on which order they are folded in. Without associativity
    /// and commutativity, the same rule could warn or not depending on field order.
    #[kani::proof]
    fn combining_dimensions_does_not_depend_on_their_order() {
        let a = any_strictness();
        let b = any_strictness();
        let c = any_strictness();

        assert!(a.and(b) == b.and(a));
        assert!(a.and(b).and(c) == a.and(b.and(c)));
    }

    /// A dimension that carries no comparison never changes the answer. That is the
    /// plan's "not applicable is not loosening", and it is stronger than the plan states
    /// it: a dimension with nothing to compare is not anything.
    #[kani::proof]
    fn a_dimension_with_nothing_to_compare_changes_nothing() {
        let a = any_strictness();
        kani::assume(a.compared());
        assert!(Strictness::NotApplicable.and(a) == a);
        assert!(Strictness::Unset.and(a) == a);
    }

    /// A dimension that did not move is an identity over every dimension that was
    /// compared.
    ///
    /// Not over the two that were not, and the difference is the point: a rule with one
    /// unchanged dimension and one that has no meaning here was compared and did not
    /// move, so it is `Same`. The non-comparisons survive only when that is all there is.
    #[kani::proof]
    fn an_unchanged_dimension_decides_nothing_that_was_compared() {
        let a = any_strictness();
        kani::assume(a.compared());
        assert!(Strictness::Same.and(a) == a);

        assert!(Strictness::Same.and(Strictness::NotApplicable) == Strictness::Same);
        assert!(Strictness::Same.and(Strictness::Unset) == Strictness::Same);
    }

    /// Nothing that carries no comparison ever warns, and combining two of them leaves
    /// the answer where it was. This is what keeps the channel readable when `defaults`
    /// is sparse, which is the ordinary shape of a real config.
    #[kani::proof]
    fn a_dimension_with_nothing_to_compare_never_warns() {
        let a = any_strictness();
        kani::assume(!a.compared());
        assert!(!a.warns());
        assert!(a.and(a) == a);
    }

    /// Combining can only ever move toward undecided, never away from it. A rule that
    /// comes out stricter had no dimension that got looser, and the other way round.
    ///
    /// This is what §5.5's "fail loud when tightening cannot be proven" means in code,
    /// and it is separate from the order-independence proof on purpose: a version that
    /// resolved a conflict by picking one side would still be commutative and
    /// associative, so that proof does not catch it.
    #[kani::proof]
    fn a_conflict_between_dimensions_is_never_resolved() {
        let a = any_strictness();
        let b = any_strictness();

        if a.and(b) == Strictness::Stricter {
            assert!(a != Strictness::Looser && b != Strictness::Looser);
        }
        if a.and(b) == Strictness::Looser {
            assert!(a != Strictness::Stricter && b != Strictness::Stricter);
        }
    }

    /// Once a rule is undecided it stays undecided: no later dimension can argue it back
    /// into being provably stricter. §5.5 fails loud, and this is what makes that
    /// unconditional.
    #[kani::proof]
    fn an_undecided_rule_cannot_be_argued_back() {
        let a = any_strictness();
        assert!(Strictness::Incomparable.and(a) == Strictness::Incomparable);
        assert!(a.and(Strictness::Incomparable) == Strictness::Incomparable);
    }

    /// A rule warns exactly when it got looser or when its direction could not be proven.
    /// Not applicable never warns, which is what keeps the channel readable.
    #[kani::proof]
    fn warning_is_exactly_loosening_or_not_knowing() {
        let a = any_strictness();
        assert_eq!(
            a.warns(),
            a == Strictness::Looser || a == Strictness::Incomparable
        );
    }

    /// The two declared directions are mirror images over every pair of values. Getting
    /// one backwards fires warnings in exactly the wrong direction, which the plan calls
    /// worse than having none.
    #[kani::proof]
    fn the_two_directions_are_mirror_images() {
        let value: u32 = kani::any();
        let baseline: u32 = kani::any();

        let higher = Direction::HigherIsStricter.strictness(value, baseline);
        let lower = Direction::LowerIsStricter.strictness(value, baseline);
        assert!(higher == lower.inverse());
        assert!(higher != Strictness::Incomparable);
        assert!(higher != Strictness::NotApplicable);
    }

    /// A numeric comparison reverses when the sides swap, like the action one.
    #[kani::proof]
    fn a_numeric_comparison_reverses_when_the_sides_swap() {
        let direction = any_direction();
        let value: u32 = kani::any();
        let baseline: u32 = kani::any();
        assert!(
            direction.strictness(value, baseline)
                == direction.strictness(baseline, value).inverse()
        );
    }

    /// Equal values never warn, whichever way the parameter runs.
    #[kani::proof]
    fn a_parameter_that_did_not_change_never_warns() {
        let direction = any_direction();
        let value: u32 = kani::any();
        assert!(direction.strictness(value, value) == Strictness::Same);
        assert!(!direction.strictness(value, value).warns());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIONS: [Action; 3] = [Action::Allow, Action::Quarantine, Action::Block];

    #[test]
    fn the_lattice_runs_allow_quarantine_block() {
        let strengths: Vec<u8> = ACTIONS.iter().map(|a| a.strength()).collect();
        assert_eq!(strengths, vec![0, 1, 2]);
    }

    #[test]
    fn moving_down_the_lattice_is_loosening() {
        assert_eq!(
            Action::Quarantine.strictness_against(Action::Block),
            Strictness::Looser
        );
        assert_eq!(
            Action::Block.strictness_against(Action::Quarantine),
            Strictness::Stricter
        );
        assert_eq!(
            Action::Quarantine.strictness_against(Action::Quarantine),
            Strictness::Same
        );
    }

    /// The plan's own example of the case that cannot be decided: `block/3d` overridden
    /// by `warn/30d` is looser in action and stricter in cooldown.
    #[test]
    fn tighter_in_one_dimension_and_looser_in_another_is_incomparable() {
        let action = Action::Quarantine.strictness_against(Action::Block);
        let days = Direction::HigherIsStricter.strictness(30, 3);
        assert_eq!(action, Strictness::Looser);
        assert_eq!(days, Strictness::Stricter);
        assert_eq!(action.and(days), Strictness::Incomparable);
        assert!(action.and(days).warns());
    }

    #[test]
    fn a_dimension_that_does_not_apply_does_not_decide_anything() {
        assert_eq!(
            Strictness::NotApplicable.and(Strictness::Looser),
            Strictness::Looser
        );
        assert_eq!(
            Strictness::NotApplicable.and(Strictness::NotApplicable),
            Strictness::NotApplicable
        );
        assert!(!Strictness::NotApplicable.warns());
        assert!(!Strictness::Same.warns());
    }

    /// The two identities are not the same identity, and the difference is worth
    /// pinning: a rule with one unchanged dimension and one that has no meaning here was
    /// compared and did not move, so it is `Same`. `NotApplicable` is what is left when
    /// there was nothing to compare at all, and that is what `explain` reports as N/A.
    #[test]
    fn unchanged_beats_not_applicable_when_they_meet() {
        assert_eq!(
            Strictness::Same.and(Strictness::NotApplicable),
            Strictness::Same
        );
        assert_eq!(
            Strictness::NotApplicable.and(Strictness::Same),
            Strictness::Same
        );
    }

    #[test]
    fn the_two_numeric_directions_run_opposite_ways() {
        assert_eq!(
            Direction::HigherIsStricter.strictness(30, 3),
            Strictness::Stricter
        );
        assert_eq!(
            Direction::LowerIsStricter.strictness(30, 3),
            Strictness::Looser
        );
        assert_eq!(
            Direction::LowerIsStricter.strictness(3, 3),
            Strictness::Same
        );
    }

    /// The table is what stops a parameter being compared one way in the merge and the
    /// other way in `policy diff`.
    #[test]
    fn every_numeric_parameter_in_the_plan_has_a_declared_direction() {
        assert_eq!(
            direction_of("cooldown.days"),
            Some(Direction::HigherIsStricter)
        );
        assert_eq!(
            direction_of("min_package_age"),
            Some(Direction::HigherIsStricter)
        );
        assert_eq!(direction_of("max_cvss"), Some(Direction::LowerIsStricter));
        assert_eq!(direction_of("cooldown.dayz"), None);
    }

    #[test]
    fn a_comparison_seen_from_the_other_side_is_its_inverse() {
        assert_eq!(Strictness::Stricter.inverse(), Strictness::Looser);
        assert_eq!(Strictness::Looser.inverse(), Strictness::Stricter);
        assert_eq!(Strictness::Same.inverse(), Strictness::Same);
        assert_eq!(Strictness::Incomparable.inverse(), Strictness::Incomparable);
        assert_eq!(
            Strictness::NotApplicable.inverse(),
            Strictness::NotApplicable
        );
        assert_eq!(Strictness::Unset.inverse(), Strictness::Unset);
    }

    /// `Unset` is the common shape in a real config, where `defaults` is sparse and
    /// ecosystems fill it in. Calling it `Same` would claim a comparison that never
    /// happened, and calling it `NotApplicable` would claim the rule has no meaning here.
    #[test]
    fn nothing_above_to_compare_against_is_neither_unchanged_nor_inapplicable() {
        assert!(!Strictness::Unset.compared());
        assert!(!Strictness::Unset.warns());
        assert_ne!(Strictness::Unset, Strictness::Same);
        assert_ne!(Strictness::Unset, Strictness::NotApplicable);
        assert_eq!(
            Strictness::Unset.and(Strictness::Looser),
            Strictness::Looser
        );
        assert_eq!(
            Strictness::NotApplicable.and(Strictness::Unset),
            Strictness::NotApplicable,
            "the one that says more survives"
        );
    }
}
