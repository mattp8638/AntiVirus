import { NavLink } from "react-router-dom";
import type { SubNavItem } from "../data/subnav";

type SubNavProps = {
  items: SubNavItem[];
};

const SubNav = ({ items }: SubNavProps) => (
  <nav className="sub-nav" aria-label="Secondary navigation">
    <ul>
      {items.map((item) => (
        <li key={item.path}>
          <NavLink
            to={item.path}
            className={({ isActive }) =>
              isActive ? "sub-nav__link is-active" : "sub-nav__link"
            }
          >
            {item.label}
          </NavLink>
        </li>
      ))}
    </ul>
  </nav>
);

export default SubNav;
