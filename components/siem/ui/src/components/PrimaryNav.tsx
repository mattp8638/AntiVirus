import { NavLink } from "react-router-dom";
import { primaryNavigation } from "../data/navigation";

const PrimaryNav = () => (
  <nav className="primary-nav" aria-label="Primary navigation">
    <div className="primary-nav__title">Perspectives</div>
    <ul>
      {primaryNavigation.map((item) => (
        <li key={item.path}>
          <NavLink
            to={item.path}
            className={({ isActive }) =>
              isActive ? "primary-nav__link is-active" : "primary-nav__link"
            }
          >
            <span className="primary-nav__label">{item.label}</span>
            <span className="primary-nav__desc">{item.description}</span>
          </NavLink>
        </li>
      ))}
    </ul>
  </nav>
);

export default PrimaryNav;
