// Copyright 2024 Canonical Ltd.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package generate

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Render an Open OnDemand portal configuration file
// from an `ood_portal.yml` configuration file.
func RenderPortal(configFile string) (out string, err error) {
	config, err := loadConfig(configFile)
	if err != nil {
		return out, err
	}

	portal, err := NewPortalConfig(config)
	if err != nil {
		return out, err
	}

	out, err = portal.Render()
	return out, err
}

// Load the contents of `ood_portal.yml`.
func loadConfig(configFile string) (config map[string]any, err error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}
