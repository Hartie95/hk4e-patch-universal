use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
    str::FromStr,
};
use crate::REGION;

const LAYOUT_MARKER_OFFSET: u64 = 0x11D0;
const OLD_VERSION_OFFSET: u64 = 0x11F4;
const NEW_VERSION_OFFSET: u64 = 0x1218;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GameVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub build: u64,
    pub revision: u64,
}

impl GameVersion {
    pub const fn new(
        major: u32,
        minor: u32,
        patch: u32,
        build: u64,
        revision: u64,
    ) -> Self {
        Self {
            major,
            minor,
            patch,
            build,
            revision,
        }
    }

    pub fn is_at_least(
        &self,
        major: u32,
        minor: u32,
        patch: u32,
    ) -> bool {
        (self.major, self.minor, self.patch) >= (major, minor, patch)
    }

    pub fn is_before(
        &self,
        major: u32,
        minor: u32,
        patch: u32,
    ) -> bool {
        (self.major, self.minor, self.patch) < (major, minor, patch)
    }

    pub fn base_version(&self) -> (u32, u32, u32) {
        (self.major, self.minor, self.patch)
    }

    // anticheat breaks on newer windows versions and wine, so use mhynot2
    pub fn use_mhynot(&self) -> bool {
        self.is_before(2, 8, 50)
    }

    // 4.8+ doesn't have ua anymore
    pub fn has_ua(&self) -> bool {
        self.is_before(4, 7, 50)
    }

    // 3.2+ doesn't have full il2cpp exports in ua anymore
    pub fn has_ua_exports(&self) -> bool {
        self.is_before(3, 1, 50)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseGameVersionError {
    InvalidFormat,
    InvalidNumber(&'static str),
}

impl fmt::Display for ParseGameVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => {
                write!(
                    f,
                    "expected major.minor.patch_build_revision"
                )
            }
            Self::InvalidNumber(field) => {
                write!(f, "invalid numeric value for {field}")
            }
        }
    }
}

impl Error for ParseGameVersionError {}

impl FromStr for GameVersion {
    type Err = ParseGameVersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.split('_');

        let version = parts
            .next()
            .ok_or(ParseGameVersionError::InvalidFormat)?;
        let build = parts
            .next()
            .ok_or(ParseGameVersionError::InvalidFormat)?;
        let revision = parts
            .next()
            .ok_or(ParseGameVersionError::InvalidFormat)?;

        if parts.next().is_some() {
            return Err(ParseGameVersionError::InvalidFormat);
        }

        let mut version_parts = version.split('.');

        let major = parse_u32(version_parts.next(), "major")?;
        let minor = parse_u32(version_parts.next(), "minor")?;
        let patch = parse_u32(version_parts.next(), "patch")?;

        if version_parts.next().is_some() {
            return Err(ParseGameVersionError::InvalidFormat);
        }

        Ok(Self {
            major,
            minor,
            patch,
            build: build
                .parse()
                .map_err(|_| ParseGameVersionError::InvalidNumber("build"))?,
            revision: revision
                .parse()
                .map_err(|_| {
                    ParseGameVersionError::InvalidNumber("revision")
                })?,
        })
    }
}

impl fmt::Display for GameVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}_{}_{}",
            self.major,
            self.minor,
            self.patch,
            self.build,
            self.revision,
        )
    }
}

pub fn read_game_version(region: REGION) -> io::Result<GameVersion> {
    let target_path = match region {
        REGION::OS => "GenshinImpact_Data/globalgamemanagers",
        REGION::CN => "YuanShen_Data/globalgamemanagers",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown region of the game".to_string(),
            ));
        }
    };

    let mut file = File::open(target_path)?;

    let layout_marker = read_u32_le(
        &mut file,
        LAYOUT_MARKER_OFFSET,
    )?;

    let text_offset = match layout_marker {
        1 => OLD_VERSION_OFFSET,
        3 => NEW_VERSION_OFFSET,
        value => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unknown globalgamemanagers layout marker: {value}"
                ),
            ));
        }
    };

    let raw_version = read_unity_string(
        &mut file,
        text_offset,
    )?;

    raw_version.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid game version {raw_version:?}: {error}"
            ),
        )
    })
}

fn read_u32_le(
    file: &mut File,
    offset: u64,
) -> io::Result<u32> {
    let mut bytes = [0u8; 4];

    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut bytes)?;

    Ok(u32::from_le_bytes(bytes))
}

fn read_unity_string(
    file: &mut File,
    text_offset: u64,
) -> io::Result<String> {
    let length = read_u32_le(file, text_offset - 4)? as usize;

    if length == 0 || length > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid version string length: {length}"),
        ));
    }

    let mut bytes = vec![0u8; length];

    file.seek(SeekFrom::Start(text_offset))?;
    file.read_exact(&mut bytes)?;

    String::from_utf8(bytes).map_err(|error| {
        io::Error::new(io::ErrorKind::InvalidData, error)
    })
}

fn parse_u32(
    value: Option<&str>,
    field: &'static str,
) -> Result<u32, ParseGameVersionError> {
    value
        .ok_or(ParseGameVersionError::InvalidFormat)?
        .parse()
        .map_err(|_| ParseGameVersionError::InvalidNumber(field))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version() {
        let version: GameVersion =
            "5.3.0_29183395_29332470".parse().unwrap();

        assert_eq!(version.major, 5);
        assert_eq!(version.minor, 3);
        assert_eq!(version.patch, 0);
        assert_eq!(version.build, 29_183_395);
        assert_eq!(version.revision, 29_332_470);
    }

    #[test]
    fn compares_base_version() {
        let version: GameVersion =
            "5.3.0_29183395_29332470".parse().unwrap();

        assert!(version.is_at_least(5, 3, 0));
        assert!(version.is_before(6, 0, 0));
    }

    #[test]
    fn formats_version() {
        let version = GameVersion::new(
            5,
            3,
            0,
            29_183_395,
            29_332_470,
        );

        assert_eq!(
            version.to_string(),
            "5.3.0_29183395_29332470"
        );
    }
}