use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Label {
    #[default]
    Unknown,
    Known {
        realm: String,
        readers: Readers,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readers {
    Everyone,
    Only(BTreeSet<String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    WouldAllow,
    WouldDeny,
}

impl Label {
    pub fn readers(realm: &str, readers: &[&str]) -> Self {
        Self::Known {
            realm: realm.to_owned(),
            readers: Readers::Only(readers.iter().map(|reader| (*reader).to_owned()).collect()),
        }
        .normalized()
    }

    pub fn normalized(&self) -> Self {
        match self {
            Self::Known { realm, .. } if !realm.is_empty() => self.clone(),
            _ => Self::Unknown,
        }
    }

    pub fn join(&self, other: &Self) -> Self {
        let (
            Self::Known { realm, readers },
            Self::Known {
                realm: other_realm,
                readers: other_readers,
            },
        ) = (self, other)
        else {
            return Self::Unknown;
        };
        if realm.is_empty() || realm != other_realm {
            return Self::Unknown;
        }
        let readers = match (readers, other_readers) {
            (Readers::Everyone, other) | (other, Readers::Everyone) => other.clone(),
            (Readers::Only(left), Readers::Only(right)) => {
                Readers::Only(left.intersection(right).cloned().collect())
            }
        };
        Self::Known {
            realm: realm.clone(),
            readers,
        }
    }

    pub fn check_audience(&self, audience: &Self) -> Decision {
        let (
            Self::Known { realm, readers },
            Self::Known {
                realm: audience_realm,
                readers: audience_readers,
            },
        ) = (self, audience)
        else {
            return Decision::WouldDeny;
        };
        if realm.is_empty() || realm != audience_realm {
            return Decision::WouldDeny;
        }
        let permitted = match (readers, audience_readers) {
            (_, Readers::Only(audience)) if audience.is_empty() => false,
            (Readers::Everyone, _) => true,
            (Readers::Only(source), Readers::Only(audience)) => {
                !source.is_empty() && audience.is_subset(source)
            }
            _ => false,
        };
        if permitted {
            Decision::WouldAllow
        } else {
            Decision::WouldDeny
        }
    }
}
