use crate::{
    cycles::Cycles,
    cycles_cost_schedule::CanisterCyclesCostSchedule,
    cycles_use_case::{CyclesUseCase, CyclesUseCaseKind},
    nominal_cycles::NominalCycles,
};
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct CompoundCycles<T: CyclesUseCaseKind + Copy + Clone> {
    real: Cycles,
    nominal: NominalCycles,
    use_case: CyclesUseCase,
    _cycles_use_case_marker: PhantomData<T>,
}

impl<T: CyclesUseCaseKind + Copy + Clone> CompoundCycles<T> {
    pub fn new(
        amount: Cycles,
        use_case_kind: T,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Self {
        let use_case = use_case_kind.cycles_use_case();
        let real = match (use_case, cost_schedule) {
            (_, CanisterCyclesCostSchedule::Normal)
            | (CyclesUseCase::NonConsumed, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::BurnedCycles, CanisterCyclesCostSchedule::Free) => amount,
            (CyclesUseCase::Memory, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::ComputeAllocation, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::IngressInduction, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::Instructions, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::RequestAndResponseTransmission, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::Uninstall, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::CanisterCreation, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::ECDSAOutcalls, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::HTTPOutcalls, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::DeletedCanisters, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::SchnorrOutcalls, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::VetKd, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::DroppedMessages, CanisterCyclesCostSchedule::Free) => Cycles::zero(),
        };
        Self {
            real,
            nominal: NominalCycles::from(amount.get()),
            use_case,
            _cycles_use_case_marker: PhantomData,
        }
    }

    pub fn real(&self) -> Cycles {
        self.real
    }

    pub fn nominal(&self) -> NominalCycles {
        self.nominal
    }

    pub fn use_case(&self) -> CyclesUseCase {
        self.use_case
    }
}

impl<T: CyclesUseCaseKind + Copy + Clone> Add for CompoundCycles<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            real: self.real + rhs.real,
            nominal: self.nominal + rhs.nominal,
            use_case: self.use_case,
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
    }
}

impl<T: CyclesUseCaseKind + Copy + Clone> AddAssign for CompoundCycles<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.real = self.real + rhs.real;
        self.nominal = self.nominal + rhs.nominal;
    }
}

impl<T: CyclesUseCaseKind + Copy + Clone> Sub for CompoundCycles<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            real: self.real - rhs.real,
            nominal: self.nominal - rhs.nominal,
            use_case: self.use_case,
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
    }
}

impl<T: CyclesUseCaseKind + Copy + Clone> SubAssign for CompoundCycles<T> {
    fn sub_assign(&mut self, rhs: Self) {
        self.real = self.real - rhs.real;
        self.nominal = self.nominal - rhs.nominal;
    }
}

impl<T: CyclesUseCaseKind + Copy + Clone> Mul<u64> for CompoundCycles<T> {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        Self {
            real: self.real * rhs,
            nominal: self.nominal * rhs,
            use_case: self.use_case,
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
    }
}

impl<T: CyclesUseCaseKind + Copy + Clone> Div<u128> for CompoundCycles<T> {
    type Output = Self;

    fn div(self, rhs: u128) -> Self {
        Self {
            real: self.real / rhs,
            nominal: self.nominal / rhs,
            use_case: self.use_case,
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
    }
}
