import { describe, it, expect, vi, beforeEach } from "vitest";
import { mount } from "@vue/test-utils";
import { ref } from "vue";

// Mock @floating-ui/vue — jsdom cannot measure DOM geometry
vi.mock("@floating-ui/vue", () => ({
  useFloating: () => ({
    floatingStyles: ref({ position: "fixed", top: "0px", left: "200px" }),
    placement: ref("right"),
    middlewareData: ref({ arrow: { x: undefined, y: 4 } }),
  }),
  flip: () => ({}),
  shift: () => ({}),
  offset: () => ({}),
  arrow: () => ({}),
  autoUpdate: vi.fn(),
}));

// Stub Teleport so the floating panel renders inline during tests
const globalConfig = {
  stubs: { Teleport: true },
};

describe("InfoPopup", () => {
  let InfoPopup: any;

  beforeEach(async () => {
    const mod = await import("./InfoPopup.vue");
    InfoPopup = mod.default;
  });

  it("is closed by default", () => {
    const wrapper = mount(InfoPopup, {
      slots: { trigger: "<button>?</button>", default: "<span>details</span>" },
      global: globalConfig,
    });
    expect(wrapper.find("[data-floating]").exists()).toBe(false);
  });

  it("opens when trigger is clicked", async () => {
    const wrapper = mount(InfoPopup, {
      slots: {
        trigger: "<button data-trigger>?</button>",
        default: "<span>details</span>",
      },
      global: globalConfig,
    });
    await wrapper.find("[data-trigger]").trigger("click");
    expect(wrapper.find("[data-floating]").exists()).toBe(true);
  });

  it("closes when trigger is clicked again", async () => {
    const wrapper = mount(InfoPopup, {
      slots: {
        trigger: "<button data-trigger>?</button>",
        default: "<span>details</span>",
      },
      global: globalConfig,
    });
    await wrapper.find("[data-trigger]").trigger("click");
    await wrapper.find("[data-trigger]").trigger("click");
    expect(wrapper.find("[data-floating]").exists()).toBe(false);
  });

  it("shows on mouseenter and hides on mouseleave", async () => {
    const wrapper = mount(InfoPopup, {
      slots: {
        trigger: "<button data-trigger>?</button>",
        default: "<span>details</span>",
      },
      global: globalConfig,
    });
    await wrapper.find("[data-trigger]").trigger("mouseenter");
    expect(wrapper.find("[data-floating]").exists()).toBe(true);
    await wrapper.find("[data-trigger]").trigger("mouseleave");
    expect(wrapper.find("[data-floating]").exists()).toBe(false);
  });

  it("renders default slot content when open", async () => {
    const wrapper = mount(InfoPopup, {
      slots: {
        trigger: "<button data-trigger>?</button>",
        default: '<span class="content">hello</span>',
      },
      global: globalConfig,
    });
    await wrapper.find("[data-trigger]").trigger("click");
    expect(wrapper.find(".content").text()).toBe("hello");
  });

  it("applies floatingStyles to the floating panel", async () => {
    const wrapper = mount(InfoPopup, {
      slots: {
        trigger: "<button data-trigger>?</button>",
        default: "<span>x</span>",
      },
      global: globalConfig,
    });
    await wrapper.find("[data-trigger]").trigger("click");
    const panel = wrapper.find("[data-floating]");
    expect(panel.attributes("style")).toContain("left: 200px");
  });
});
